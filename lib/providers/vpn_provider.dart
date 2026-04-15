import 'dart:async';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:permission_handler/permission_handler.dart';
import '../core/interfaces/vpn_engine.dart';

import '../core/models/vpn_stats.dart';
import '../core/services/log_service.dart';
import '../core/services/settings_service.dart';
import '../protocols/xray/xray_engine.dart';
import 'settings_provider.dart';
import 'config_provider.dart';

class VpnState2 {
  final VpnState connectionState;
  final VpnStats stats;
  final String? error;

  const VpnState2({
    this.connectionState = VpnState.disconnected,
    this.stats = const VpnStats(),
    this.error,
  });

  bool get isConnected => connectionState == VpnState.connected;
  bool get isConnecting => connectionState == VpnState.connecting;
  bool get isDisconnecting => connectionState == VpnState.disconnecting;
  bool get isBusy => isConnecting || isDisconnecting;

  VpnState2 copyWith({
    VpnState? connectionState,
    VpnStats? stats,
    String? error,
  }) {
    return VpnState2(
      connectionState: connectionState ?? this.connectionState,
      stats: stats ?? this.stats,
      error: error,
    );
  }
}

class VpnNotifier extends Notifier<VpnState2> {
  late final XrayEngine _engine;
  StreamSubscription<VpnState>? _stateSub;
  StreamSubscription<VpnStats>? _statsSub;
  StreamSubscription<dynamic>? _logSub;
  ({String user, String password})? _socksCredentials;

  @override
  VpnState2 build() {
    _engine = XrayEngine();

    _stateSub = _engine.stateStream.listen((s) {
      if (state.connectionState != s) {
        state = state.copyWith(connectionState: s);
      }
    });

    _statsSub = _engine.statsStream.listen((newStats) {
      // Only update if stats significantly changed to reduce UI pressure
      if (state.stats.uploadBytes != newStats.uploadBytes || 
          state.stats.downloadBytes != newStats.downloadBytes) {
        state = state.copyWith(stats: newStats);
      }
    });

    _logSub = _engine.logStream.listen((entry) {
      ref.read(logServiceProvider.notifier).add(entry);
    });

    ref.onDispose(() {
      _stateSub?.cancel();
      _statsSub?.cancel();
      _logSub?.cancel();
      _engine.dispose();
    });

    return const VpnState2();
  }

  Future<void> connect() async {
    // Request notification permission for foreground service (Android 13+)
    await Permission.notification.request();

    final configState = ref.read(configProvider).maybeWhen(data: (d) => d, orElse: () => null);
    final config = configState?.activeConfig;
    if (config == null) {
      ref.read(logServiceProvider.notifier).addError('No configuration selected');
      return;
    }

    final settings = ref.read(settingsProvider).maybeWhen(data: (d) => d, orElse: () => null) ?? const AppSettings();

    // Generate credentials
    if (settings.randomCredentials) {
      _socksCredentials = XrayEngine.generateSocksCredentials();
    } else {
      _socksCredentials = (user: settings.socksUser, password: settings.socksPassword);
    }

    // Use random port or configured port
    final actualSocksPort = settings.randomPort
        ? (10000 + DateTime.now().millisecondsSinceEpoch % 50000)
        : settings.socksPort;

    final options = VpnEngineOptions(
      socksPort: actualSocksPort,
      httpPort: 0,
      socksUser: _socksCredentials!.user,
      socksPassword: _socksCredentials!.password,
      excludedPackages: settings.splitTunnelingEnabled
          ? (settings.vpnMode == VpnMode.allExcept
              ? settings.excludedPackages
              : <String>{})
          : {},
      includedPackages: settings.splitTunnelingEnabled
          ? (settings.vpnMode == VpnMode.onlySelected
              ? settings.includedPackages
              : <String>{})
          : {},
      logLevel: settings.logLevel,
      enableUdp: settings.enableUdp,
      dnsMode: settings.dnsMode,
      dnsServer: settings.dnsServer,
      vpnMode: settings.vpnMode,
      proxyOnly: settings.proxyOnly,
      showNotification: settings.showNotification,
    );

    await _engine.connect(config, options);
  }

  Future<void> disconnect() async {
    await _engine.disconnect();
  }

  /// Syncs the Flutter VPN state with the native service state.
  /// Called when the app resumes from background or after the Activity is recreated.
  ///
  /// Routes through [_engine.syncState] so that both XrayEngine._state and
  /// the Riverpod layer agree — if we patched Riverpod directly the engine's
  /// disconnect() guard would see a stale "disconnected" and become a no-op.
  Future<void> syncNativeState() async {
    // Skip during active transitions. The engine already knows the current
    // state via EventChannel. Overriding here would race with an in-progress
    // connect() — e.g. permission dialogs cause pause→resume which fires this
    // method while connect() is still awaiting the native reply.
    final engineState = _engine.currentState;
    if (engineState == VpnState.connecting ||
        engineState == VpnState.disconnecting) return;

    try {
      const channel = MethodChannel('com.teapodstream/vpn');
      final nativeState = await channel.invokeMethod<String>('getState');
      if (nativeState == null) return;

      final mappedState = switch (nativeState) {
        'connected'    => VpnState.connected,
        'connecting'   => VpnState.connecting,
        'error'        => VpnState.error,
        _              => VpnState.disconnected,
      };

      // syncState emits on stateStream → _stateSub → Riverpod state update.
      // It also restarts stats polling when connected.
      _engine.syncState(mappedState);
    } catch (_) {
      // If sync fails, leave the state as-is
    }
  }

  Future<void> toggle() async {
    if (state.isBusy) return; // already transitioning — ignore tap
    if (state.isConnected) {
      await disconnect();
    } else {
      await connect();
    }
  }

  VpnState get connectionState => state.connectionState;
}

final vpnProvider = NotifierProvider<VpnNotifier, VpnState2>(VpnNotifier.new);

// Convenience selector for connection state
final vpnConnectionStateProvider = Provider<VpnState>((ref) {
  return ref.watch(vpnProvider).connectionState;
});

// Convenience selector for stats
final vpnStatsProvider = Provider<VpnStats>((ref) {
  return ref.watch(vpnProvider).stats;
});

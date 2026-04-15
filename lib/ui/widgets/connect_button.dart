
import 'package:flutter/material.dart';
import '../../core/interfaces/vpn_engine.dart';
import '../theme/app_colors.dart';

class ConnectButton extends StatefulWidget {
  final VpnState state;
  final VoidCallback? onTap;

  const ConnectButton({super.key, required this.state, this.onTap});

  @override
  State<ConnectButton> createState() => _ConnectButtonState();
}

class _ConnectButtonState extends State<ConnectButton>
    with SingleTickerProviderStateMixin {
  late final AnimationController _controller;
  late final Animation<double> _pulseAnim;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1500),
    );
    _pulseAnim = Tween<double>(begin: 1.0, end: 1.15).animate(
      CurvedAnimation(parent: _controller, curve: Curves.easeInOut),
    );
    _syncAnimation();
  }

  @override
  void didUpdateWidget(ConnectButton old) {
    super.didUpdateWidget(old);
    if (old.state != widget.state) {
      _syncAnimation();
    }
  }

  void _syncAnimation() {
    if (widget.state == VpnState.connecting) {
      _controller.repeat(reverse: true);
    } else {
      _controller.stop();
      _controller.reset();
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  Color get _outerColor => switch (widget.state) {
        VpnState.connected => AppColors.connectedDim.withValues(alpha: 0.3),
        VpnState.connecting => AppColors.connecting.withValues(alpha: 0.2),
        VpnState.error => AppColors.error.withValues(alpha: 0.2),
        _ => AppColors.primaryDim.withValues(alpha: 0.2),
      };

  Color get _innerColor => switch (widget.state) {
        VpnState.connected => AppColors.connected,
        VpnState.connecting => AppColors.connecting,
        VpnState.disconnecting => AppColors.connecting,
        VpnState.error => AppColors.error,
        _ => AppColors.primary,
      };

  String get _label => switch (widget.state) {
        VpnState.connected => 'ОТКЛЮЧИТЬ',
        VpnState.connecting => 'ПОДКЛЮЧЕНИЕ...',
        VpnState.disconnecting => 'ОТКЛЮЧЕНИЕ...',
        VpnState.error => 'ОШИБКА',
        _ => 'ПОДКЛЮЧИТЬ',
      };

  bool get _enabled =>
      widget.state == VpnState.connected ||
      widget.state == VpnState.disconnected ||
      widget.state == VpnState.error;

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _pulseAnim,
      builder: (context, child) {
        return GestureDetector(
          onTap: _enabled ? widget.onTap : null,
          child: Stack(
            alignment: Alignment.center,
            children: [
              // Outer glow ring (animated via Transform.scale to avoid layout shifts)
              Transform.scale(
                scale: _pulseAnim.value,
                child: Container(
                  width: 200,
                  height: 200,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: _outerColor,
                  ),
                ),
              ),
              // Middle ring
              Container(
                width: 168,
                height: 168,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: _innerColor.withValues(alpha: 0.15),
                  border: Border.all(
                    color: _innerColor.withValues(alpha: 0.4),
                    width: 1.5,
                  ),
                ),
              ),
              // Main button
              Container(
                width: 140,
                height: 140,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  gradient: RadialGradient(
                    colors: [
                      _innerColor.withValues(alpha: 0.9),
                      _innerColor,
                    ],
                  ),
                  boxShadow: [
                    BoxShadow(
                      color: _innerColor.withValues(alpha: 0.4),
                      blurRadius: 30,
                      spreadRadius: 2,
                    ),
                  ],
                ),
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Icon(
                      widget.state == VpnState.connected
                          ? Icons.power_settings_new
                          : Icons.power_settings_new_outlined,
                      color: Colors.white,
                      size: 48,
                    ),
                    const SizedBox(height: 6),
                    Text(
                      _label,
                      style: const TextStyle(
                        color: Colors.white,
                        fontSize: 10,
                        fontWeight: FontWeight.w700,
                        letterSpacing: 1.2,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        );
      },
    );
  }
}

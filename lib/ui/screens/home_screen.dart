import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../providers/vpn_provider.dart';
import '../../providers/config_provider.dart';
import '../../providers/ip_info_provider.dart';
import '../theme/app_colors.dart';
import '../widgets/connect_button.dart';
import '../widgets/stats_card.dart';
import '../widgets/config_card.dart';

class HomeScreen extends ConsumerWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final vpnState = ref.watch(vpnProvider);
    final configState = ref.watch(configProvider);

    return Scaffold(
      body: SafeArea(
        child: CustomScrollView(
          slivers: [
            SliverToBoxAdapter(
              child: Padding(
                padding: const EdgeInsets.fromLTRB(20, 32, 20, 0),
                child: const _AppTitle(),
              ),
            ),
            // Connect button
            SliverToBoxAdapter(
              child: Padding(
                padding: const EdgeInsets.symmetric(vertical: 40),
                child: Center(
                  child: ConnectButton(
                    state: vpnState.connectionState,
                    onTap: configState.maybeWhen(data: (d) => d, orElse: () => null)?.activeConfig != null
                        ? () => ref.read(vpnProvider.notifier).toggle()
                        : null,
                  ),
                ),
              ),
            ),
            // Active config card
            SliverToBoxAdapter(
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 20),
                child: _ActiveConfigSection(ref: ref),
              ),
            ),
            const SliverToBoxAdapter(child: SizedBox(height: 16)),
            // IP info (visible only when connected)
            if (vpnState.isConnected)
              SliverToBoxAdapter(
                child: Padding(
                  padding: const EdgeInsets.fromLTRB(20, 0, 20, 16),
                  child: const _IpInfoCard(),
                ),
              ),
            // Stats
            SliverToBoxAdapter(
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 20),
                child: StatsCard(
                  stats: vpnState.stats,
                  connectionState: vpnState.connectionState,
                ),
              ),
            ),
            const SliverToBoxAdapter(child: SizedBox(height: 24)),
          ],
        ),
      ),
    );
  }
}

class _AppTitle extends StatelessWidget {
  const _AppTitle();

  @override
  Widget build(BuildContext context) {
    return const Center(
      child: Text(
        'TeapodStream',
        style: TextStyle(
          color: AppColors.textPrimary,
          fontSize: 24,
          fontWeight: FontWeight.w700,
        ),
      ),
    );
  }
}

class _ActiveConfigSection extends StatelessWidget {
  final WidgetRef ref;
  const _ActiveConfigSection({required this.ref});

  @override
  Widget build(BuildContext context) {
    final configState = ref.watch(configProvider);
    final activeConfig = configState.maybeWhen(data: (d) => d, orElse: () => null)?.activeConfig;
    final vpnState = ref.watch(vpnProvider);

    if (activeConfig == null) {
      return GestureDetector(
        onTap: () => _navigateToConfigs(context),
        child: Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: AppColors.surface,
            borderRadius: BorderRadius.circular(16),
            border: Border.all(
              color: AppColors.border,
              style: BorderStyle.solid,
            ),
          ),
          child: Row(
            children: [
              Container(
                width: 40,
                height: 40,
                decoration: BoxDecoration(
                  color: AppColors.surfaceHighlight,
                  borderRadius: BorderRadius.circular(10),
                ),
                child: const Icon(
                  Icons.add_rounded,
                  color: AppColors.primary,
                ),
              ),
              const SizedBox(width: 14),
              const Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Конфигурация не выбрана',
                      style: TextStyle(
                        color: AppColors.textPrimary,
                        fontWeight: FontWeight.w500,
                      ),
                    ),
                    Text(
                      'Нажмите чтобы добавить',
                      style: TextStyle(
                        color: AppColors.textSecondary,
                        fontSize: 12,
                      ),
                    ),
                  ],
                ),
              ),
              const Icon(
                Icons.chevron_right_rounded,
                color: AppColors.textSecondary,
              ),
            ],
          ),
        ),
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Активная конфигурация',
          style: TextStyle(
            color: AppColors.textSecondary,
            fontSize: 12,
            fontWeight: FontWeight.w500,
            letterSpacing: 0.5,
          ),
        ),
        const SizedBox(height: 8),
        ConfigCard(
          config: activeConfig,
          isActive: true,
          isConnected: vpnState.isConnected,
          onTap: () => _navigateToConfigs(context),
        ),
      ],
    );
  }

  void _navigateToConfigs(BuildContext context) {
    // Tab navigation is handled by the shell
    DefaultTabController.of(context).animateTo(1);
  }
}

class _IpInfoCard extends ConsumerWidget {
  const _IpInfoCard();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final ipInfoAsync = ref.watch(ipInfoProvider);

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppColors.border),
      ),
      child: Row(
        children: [
          const Icon(Icons.location_on_rounded, size: 16, color: AppColors.textSecondary),
          const SizedBox(width: 8),
          ipInfoAsync.when(
            loading: () => const Text(
              'Определение IP...',
              style: TextStyle(color: AppColors.textSecondary, fontSize: 13),
            ),
            error: (e, st) => const Text(
              'IP недоступен',
              style: TextStyle(color: AppColors.textSecondary, fontSize: 13),
            ),
            data: (info) {
              if (info == null) {
                return const Text(
                  'IP недоступен',
                  style: TextStyle(color: AppColors.textSecondary, fontSize: 13),
                );
              }
              return Text(
                '${info.ip}  ·  ${info.country}',
                style: const TextStyle(
                  color: AppColors.textPrimary,
                  fontSize: 13,
                  fontWeight: FontWeight.w500,
                ),
              );
            },
          ),
        ],
      ),
    );
  }
}

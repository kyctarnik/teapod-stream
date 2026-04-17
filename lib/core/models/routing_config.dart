enum RoutingMode {
  global,
  bypassLocal,
  bypassRU,
  bypassCN,
  onlyRU,
}

extension RoutingModeInfo on RoutingMode {
  String get title => switch (this) {
        RoutingMode.global => 'Глобальный',
        RoutingMode.bypassLocal => 'Обход локальных',
        RoutingMode.bypassRU => 'Обход RU',
        RoutingMode.bypassCN => 'Обход CN',
        RoutingMode.onlyRU => 'Только RU',
      };

  String get subtitle => switch (this) {
        RoutingMode.global => 'Весь трафик через VPN',
        RoutingMode.bypassLocal => 'Локальные сети напрямую',
        RoutingMode.bypassRU => 'Российские ресурсы напрямую',
        RoutingMode.bypassCN => 'Китайский трафик напрямую',
        RoutingMode.onlyRU => 'Только RU через VPN, остальное напрямую',
      };
}

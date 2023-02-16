# RST THREAT FEED (all)

[![GitHub license](https://img.shields.io/badge/LICENSE-MIT-GREEN?style=for-the-badge)](LICENSE)
[![Last Updated](https://img.shields.io/github/actions/workflow/status/elliotwutingfeng/rstthreatsall/update.yml?branch=main&label=Last%20Updated&style=for-the-badge)](https://github.com/elliotwutingfeng/rstthreatsall/actions/workflows/update.yml)
<img src="https://tokei-rs.onrender.com/b1/github/elliotwutingfeng/rstthreatsall?label=Total%20Domains%20%26%20IPs%20(Short)&style=for-the-badge" alt="Total Domains & IPs (Short)"/>

Aggregated Indicators of Compromise collected and cross-verified from multiple open and community-supported sources by [RST Cloud](https://rstcloud.com).

This repository consolidates all unique IOCs ever released at [rstthreats](https://github.com/rstcloud/rstthreats) and their "last seen" timestamps (in UNIX seconds) into **.txt** files. Updated at least once a day.

## Testing

```bash
make test
```

## Usage

This repository will not be monitored for false-positives. Some of the listed IOCs have last seen timestamps dating back to 2022. If you intend to use this as a firewall blocklist, you are encouraged to filter out older entries beforehand.

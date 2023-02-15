# RST THREAT FEED (all)

[![GitHub license](https://img.shields.io/badge/LICENSE-MIT-GREEN?style=for-the-badge)](LICENSE)

Aggregated Indicators of Compromise collected and cross-verified from multiple open and community-supported sources by [RST Cloud](https://github.com/rstcloud/rstthreats).

This repository consolidates all unique **random100** IOCs ever released at [rstthreats](https://github.com/rstcloud/rstthreats) and their "last seen" timestamps into **.txt** files. Updated at least once a day.

## Testing

```bash
python -m coverage run -m unittest -f extract.py && python -m coverage html
```

# Curve DAO benchmark

- Auditor: Trail of Bits
- Audited commit: `f1c8f4351a9d6a34a7e4227712dff8eecf74ae66`
- Vyper Guard: `0.6.0`
- Source integrity: sha256_verified

## Result

- Published audit findings: 21
- Findings supported by current detectors: 1
- Supported benchmark locations: 13
- Locations rediscovered: 0
- Supported-case recall: 0.0%
- Scanner candidates: 41
- Unreviewed candidates: 41
- Precision: not measured; candidates have not been independently reviewed

## Supported cases

| Case | File | Function | Detector | Result |
| --- | --- | --- | --- | --- |
| TOB-CURVE-DAO-013-01 | `PoolProxy.vy` | `set_admins` | `missing_event_emission` | **missed** |
| TOB-CURVE-DAO-013-02 | `PoolProxy.vy` | `set_burner` | `missing_event_emission` | **missed** |
| TOB-CURVE-DAO-013-03 | `ERC20CRV.vy` | `update_mining_parameters` | `missing_event_emission` | **missed** |
| TOB-CURVE-DAO-013-04 | `ERC20CRV.vy` | `set_minter` | `missing_event_emission` | **missed** |
| TOB-CURVE-DAO-013-05 | `ERC20CRV.vy` | `set_admin` | `missing_event_emission` | **missed** |
| TOB-CURVE-DAO-013-06 | `GaugeController.vy` | `transfer_ownership` | `missing_event_emission` | **missed** |
| TOB-CURVE-DAO-013-07 | `GaugeController.vy` | `_change_type_weight` | `missing_event_emission` | **missed** |
| TOB-CURVE-DAO-013-08 | `GaugeController.vy` | `_change_gauge_weight` | `missing_event_emission` | **missed** |
| TOB-CURVE-DAO-013-09 | `GaugeController.vy` | `vote_for_gauge_weights` | `missing_event_emission` | **missed** |
| TOB-CURVE-DAO-013-10 | `LiquidityGauge.vy` | `_update_liquidity_limit` | `missing_event_emission` | **missed** |
| TOB-CURVE-DAO-013-11 | `VotingEscrow.vy` | `transfer_ownership` | `missing_event_emission` | **missed** |
| TOB-CURVE-DAO-013-12 | `VotingEscrow.vy` | `add_to_whitelist` | `missing_event_emission` | **missed** |
| TOB-CURVE-DAO-013-13 | `VotingEscrow.vy` | `remove_from_whitelist` | `missing_event_emission` | **missed** |

## Interpretation

This benchmark measures only detector behavior that maps directly to published audit
evidence. Unsupported findings remain visible as coverage gaps. Scanner candidates are
not called false positives until a reviewer labels them.

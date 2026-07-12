# Curve DAO benchmark

- Auditor: Trail of Bits
- Audited commit: `f1c8f4351a9d6a34a7e4227712dff8eecf74ae66`
- Vyper Guard: `0.6.0`
- Source integrity: sha256_verified

## Result

- Published audit findings: 21
- Findings supported by current detectors: 1
- Supported benchmark locations: 13
- Locations rediscovered: 9
- Supported-case recall: 69.2%
- Scanner candidates: 37
- Unreviewed candidates: 0
- Strict finding precision: 24.3%
- Review status: complete_internal_review
- Independent review: no
- Confirmed new issues: 0
- Known issues rediscovered: 9
- Audit-related observations: 5
- Hardening recommendations: 9
- False positives: 14
- False-positive rate: 37.8%

## Validated detector scope

- Detectors: `missing_event_emission`
- Findings: 16
- Recall: 69.2%
- Strict precision: 56.2%
- Actionable observation rate: 81.2%
- False positives: 3
- Review is internal, not independent

## Supported cases

| Case | File | Function | Detector | Result |
| --- | --- | --- | --- | --- |
| TOB-CURVE-DAO-013-01 | `PoolProxy.vy` | `set_admins` | `missing_event_emission` | **rediscovered** |
| TOB-CURVE-DAO-013-02 | `PoolProxy.vy` | `set_burner` | `missing_event_emission` | **rediscovered** |
| TOB-CURVE-DAO-013-03 | `ERC20CRV.vy` | `update_mining_parameters` | `missing_event_emission` | **missed** |
| TOB-CURVE-DAO-013-04 | `ERC20CRV.vy` | `set_minter` | `missing_event_emission` | **rediscovered** |
| TOB-CURVE-DAO-013-05 | `ERC20CRV.vy` | `set_admin` | `missing_event_emission` | **rediscovered** |
| TOB-CURVE-DAO-013-06 | `GaugeController.vy` | `transfer_ownership` | `missing_event_emission` | **rediscovered** |
| TOB-CURVE-DAO-013-07 | `GaugeController.vy` | `_change_type_weight` | `missing_event_emission` | **missed** |
| TOB-CURVE-DAO-013-08 | `GaugeController.vy` | `_change_gauge_weight` | `missing_event_emission` | **missed** |
| TOB-CURVE-DAO-013-09 | `GaugeController.vy` | `vote_for_gauge_weights` | `missing_event_emission` | **rediscovered** |
| TOB-CURVE-DAO-013-10 | `LiquidityGauge.vy` | `_update_liquidity_limit` | `missing_event_emission` | **missed** |
| TOB-CURVE-DAO-013-11 | `VotingEscrow.vy` | `transfer_ownership` | `missing_event_emission` | **rediscovered** |
| TOB-CURVE-DAO-013-12 | `VotingEscrow.vy` | `add_to_whitelist` | `missing_event_emission` | **rediscovered** |
| TOB-CURVE-DAO-013-13 | `VotingEscrow.vy` | `remove_from_whitelist` | `missing_event_emission` | **rediscovered** |

## Detector evidence

| Detector | Maturity | Cases | Rediscovered | Recall | Candidates | Precision |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `missing_event_emission` | experimental | 13 | 9 | 69.2% | 16 | 56.2% |
| `missing_input_validation` | experimental | 0 | 0 | n/a | 3 | 0.0% |
| `missing_zero_address_check` | experimental | 0 | 0 | n/a | 10 | 0.0% |
| `tx_origin_auth` | supported | 0 | 0 | n/a | 1 | 0.0% |
| `unchecked_subtraction` | experimental | 0 | 0 | n/a | 7 | 0.0% |

## Interpretation

This benchmark measures only detector behavior that maps directly to published audit
evidence. Unsupported findings remain visible as coverage gaps. Scanner candidates are
not called false positives until a reviewer labels them.

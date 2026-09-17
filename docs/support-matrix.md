# Version-aware support matrix

States: **Implemented + Tested**, **Implemented + Untested**, **Documented, not implemented**, **Not verified**, **Not applicable**.

| Feature | ASA 9.20 | ASA 9.22 | ASA 9.24 | FortiOS 7.4 | FortiOS 7.6 | PAN-OS 11.1 | PAN-OS 12.1 |
|---|---|---|---|---|---|---|---|
| Addresses/groups | Not verified | Not verified | Not verified | Not verified | Not verified | Not verified | Not verified |
| Services/groups | Not verified | Not verified | Not verified | Not verified | Not verified | Not verified | Not verified |
| Security policy | Not verified | Not verified | Not verified | Not verified | Not verified | Implemented + Tested | Not verified |
| Static routes | Not verified | Not verified | Not verified | Not verified | Not verified | Not verified | Not verified |
| Interface PAT | Not applicable | Not applicable | Not applicable | Implemented + Tested | Implemented + Tested | Not verified | Not verified |
| VIP static/port DNAT | Not applicable | Not applicable | Not applicable | Implemented + Tested | Implemented + Tested | Not verified | Not verified |
| ASA static NAT/PAT | Not verified | Not verified | Not verified | Not applicable | Not applicable | Not verified | Not verified |
| IP pools / central NAT | Not applicable | Not applicable | Not applicable | Documented, not implemented | Documented, not implemented | Not applicable | Not applicable |
| VDOM / SD-WAN / profiles | Not applicable | Not applicable | Not applicable | Documented, not implemented | Documented, not implemented | Not applicable | Not applicable |

The matrix describes individual implementation evidence, not end-to-end conversion assurance. No current pair has complete source and target evidence for all emitted command categories; unverified entities downgrade to manual review.
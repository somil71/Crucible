# Virtual Time Contract & Discrete Event Semantics

Crucible guarantees strict discrete-event simulation monotonicity across all virtual entities.

$$\forall e_i, e_j \in \mathcal{E}: e_i \prec e_j \implies t(e_i) \le t(e_j)$$

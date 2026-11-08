# Hierarchical Delta-Debugging (HDD) Theoretical Framework

Minimizes failure-inducing fault sequences from $N$ noisy events down to $k \le 5$ causal events using binary division.

$$c_{min} = \arg\min_{c \subseteq S} \{|c| : \text{fails}(c) = \text{true}\}$$

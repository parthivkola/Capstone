# Research Glossary

| Term | Definition in this project |
| --- | --- |
| flow | A network communication record or observed traffic unit used for detection and, where applicable, a flow-scoped mitigation decision. |
| feature | A measured or derived input variable available under the protocol's data contract and supplied to a model. |
| attack family | A dataset-defined group of related malicious activities or labels used as a reporting and, for RQ2, held-out unit. |
| known attack | An attack class or family represented in the permitted training labels for a known-class protocol. |
| novel behavior | Activity absent from the permitted training classes or baseline and evaluated as potential unknown or anomalous behavior. |
| OOD | Out-of-distribution; behavior whose relevant characteristics are outside the training distribution or known-class support used by a model. |
| concept drift | A change over time in the relationship between observed traffic features, labels, or their distributions that can reduce a model's later-window performance. |
| drift detection | The pre-defined process for identifying a persistent signal that permits evaluation of a bounded adaptation update. |
| adaptation | A bounded model update or response to measured drift, evaluated against a no-update baseline. |
| retraining | Rebuilding or updating a model using a declared set of verified labelled data. |
| continual learning | Ongoing learning from a sequence of data. This project does not claim fully autonomous continual learning; adaptation requires declared conditions and verified labels. |
| GraphSAGE | A graph neural network candidate that aggregates information from neighbouring nodes. It is included only if a leakage-free host/flow graph can be defined. |
| SHAP | A family of feature-attribution methods that can be considered for explaining a model output. Use is contingent on a consistent fidelity and stability evaluation plan. |
| GNNExplainer | A graph-neural-network explanation method that can identify influential graph structure and features. Use is contingent on a consistent fidelity and stability evaluation plan. |
| false positive | A benign event or flow incorrectly labelled, alerted on, or mitigated as malicious under the relevant protocol. |
| false negative | A malicious labelled event or flow incorrectly treated as benign or not detected under the relevant protocol. |
| macro F1 | The unweighted mean of the F1 scores calculated for each class, giving each class equal contribution regardless of frequency. |
| FPR | False-positive rate: the fraction of benign cases incorrectly classified or flagged as positive, under the stated positive-class and threshold definition. |
| mitigation latency | In live evaluation, the time from the declared alert or policy-decision point to the observable effect of the installed mitigation rule, using a documented timestamp convention. |
| risk | The policy's categorisation of the potential consequence of an alert and action, based on declared evidence and guardrails. |
| confidence | A model or decision score indicating strength of support for an output where that score is available and documented. |
| containment | The intended malicious test flow being limited or blocked within the measured response window without violating the protected-flow rule. |
| protected flow | Traffic configured as exempt from disruptive automated mitigation because its availability is explicitly protected during the live evaluation. |
| TTL | Time to live: the configured expiry period after which a temporary mitigation rule is removed or no longer applies. |
| rollback | The documented reversal of a mitigation action, including rule removal or expiry, used to bound the effect of an erroneous action. |


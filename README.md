paillier.jar is a lightly modified version of the software made available at http://www.cs.utdallas.edu/dspl/cgi-bin/pailliertoolbox/  My contributions were focused on the serialization/deserialization of PaillierPrivateThresholdKey objects, which was bugged in the original release.  This jar is a dependency for every single participant.

mysql-connector.jar is the standard connector.  All Client* require this jar to access their local databases.

AggregatorServer and ClientServer are rough drafts; code and structure were significantly improved.

This software is expected to be run in a network.  KeyMaster and five ClientSSH instances are expected to be running before any Aggregator is run.  In practice, wait for "RSA Key Pair Generated!" to be displayed by each client to indicate that it has "booted up" fully.

AggregatorSSH and AggregatorCloud are the same software but expected to be run from different locations.  AggregatorSSH is meant to be run from local hardware and uses the public IPs of Amazon EC2 instances.  AggregatorCloud is meant to be run from the cloud and uses private IPs.



# TA-cveicu inputs.conf.spec
# Documentation for modular input configuration

[cveicu://<name>]
* Ingests CVE V5 records from the GitHub CVEProject/cvelistV5 repository.
* Downloads baseline and delta ZIP files for efficient bulk processing.

# Note: 'index' is a standard Splunk parameter and handled internally

interval = <number>
* Required. How often to run the input, in seconds.
* Default: 3600

include_adp = <boolean>
* Optional. Include ADP (Authorized Data Publisher) container data.
* ADP containers include CISA-ADP enrichment and CVE Program Container data.
* Default: true

include_rejected = <boolean>
* Optional. Include CVEs with REJECTED state.
* Set to false to exclude rejected/withdrawn CVE records.
* Default: false

batch_size = <number>
* Optional. Number of CVE records to process per batch.
* Larger batches are more efficient but use more memory.
* Default: 500

# NOTE: GitHub Personal Access Token is stored securely via Splunk's
# storage/passwords REST API. See README for configuration instructions.

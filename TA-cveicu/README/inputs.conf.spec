# TA-cveicu inputs.conf.spec
# Documentation for modular input configuration

[cveicu://<name>]
* Ingests CVE V5 records from the GitHub CVEProject/cvelistV5 repository.
* Downloads baseline and delta ZIP files for efficient bulk processing.

# Note: 'index' is a standard Splunk parameter and handled internally

include_adp = <boolean>
* Optional. Include ADP (Authorized Data Publisher) container data.
* ADP containers include CISA-ADP enrichment and CVE Program Container data.
* Default: true

include_rejected = <boolean>
* Optional. Include CVEs with REJECTED state.
* Set to false to exclude rejected/withdrawn CVE records.
* Default: true

batch_size = <number>
* Optional. Number of CVE records to process per batch.
* Larger batches are more efficient but use more memory.
* Default: 500

# NOTE: GitHub Personal Access Token is stored securely via the Setup page
# and NOT in inputs.conf. See README for configuration instructions.

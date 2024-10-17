from __future__ import annotations

import hashlib

from assemblyline import odm
from assemblyline.common import forge

Classification = forge.get_classification()

SUBMISSION_STATES = ['failed', 'submitted', 'completed']
DEFAULT_SRV_SEL = ["Filtering", "Antivirus", "Static Analysis", "Extraction", "Networking"]
DEFAULT_RESUBMIT = []


@odm.model(index=True, store=False, description="""Contains details about the individual files included in the submission, including their names, sizes, and SHA256 hashes.
""")
class File(odm.Model):
    name = odm.Keyword(copyto="__text__", description="The original name of the file as it was submitted.")
    size = odm.Optional(odm.Integer(), description="The file's size in bytes.")
    sha256 = odm.SHA256(copyto="__text__", description="The SHA256 cryptographic hash of the file, serving as a unique identifier for the file's content.")


@odm.model(index=False, store=False, description="""Outlines the services selected for analysis, any excluded services, and any additional services that should be used in the case of rescan or resubmit actions.
""")
class ServiceSelection(odm.Model):
    selected = odm.List(odm.Keyword(), default=DEFAULT_SRV_SEL, description="Services and/or service groups selected to process the submission, which determine the scope of analysis.")
    excluded = odm.List(odm.Keyword(), default=[], description="Services and/or service groups explicitly excluded from processing the submission, bypassing their analysis.")
    rescan = odm.List(
        odm.Keyword(),
        default=[],
        description="Services and/or service groups to be used for a rescan if the submission's initial results are deemed malicious.")
    resubmit = odm.List(odm.Keyword(), default=DEFAULT_RESUBMIT,
                        description="Additional services that are added to the selection when a submission is resubmitted.")


# Fields in the parameters used to calculate hashes used for result caching
_KEY_HASHED_FIELDS = {
    'classification',
    'deep_scan',
    'ignore_cache',
    'ignore_recursion_prevention',
    # TODO: This one line can be removed after assemblyline upgrade to version 4.6+
    'ignore_dynamic_recursion_prevention',
    'ignore_filtering',
    'ignore_size',
    'max_extracted',
    'max_supplementary',
}


@odm.model(index=True, store=False, description="""Specifies the parameters set at the time of submission, such as whether to perform a deep scan, if the submission should generate an alert, and any specific service selections or settings.
""")
class SubmissionParams(odm.Model):
    classification = odm.Classification(default=Classification.UNRESTRICTED,
                                        description="The initial security classification for the submission, indicating its confidentiality.")
    deep_scan = odm.Boolean(default=False, description="Enables a comprehensive examination of the submission by lifting standard safeguards and constraints, utilizing experimental methods and allowing for the exploration of potentially ambiguous findings to maximize the extraction of information.")
    description = odm.Text(store=True, copyto="__text__", description="A narrative that outlines the content and purpose of the submission.")
    generate_alert = odm.Boolean(default=False, description="Determines if an alert should be generated upon analysis completion.")
    groups = odm.List(odm.Keyword(), default=[], description="A list of group identifiers relevant to this submission, often used for access control.")
    ignore_cache = odm.Boolean(default=False, description="Bypasses any cached results for services, forcing all services to process the submission anew.")
    ignore_recursion_prevention = odm.Boolean(
        default=False, description="Overrides the default mechanism that prevents recursive scanning of extracted files.")

    # TODO: The following three lines can be removed after assemblyline upgrade to 4.6+
    ignore_dynamic_recursion_prevention = odm.Boolean(
        default=False, description="Disables dynamic recursion prevention for this submission.")

    ignore_filtering = odm.Boolean(default=False, description="**TODO**: **Original**:Should we ignore filtering services? **Generated**:Indicates if filtering services should be skipped, allowing all files to be processed.")
    ignore_size = odm.Boolean(default=False, description="Allows the submission to bypass any file size restrictions set by the system.")
    never_drop = odm.Boolean(default=False, description="Ensures the submission will not be dropped by the ingestion service, regardless of system load.")
    malicious = odm.Boolean(default=False, description="**TODO**: **Original**:Is the file submitted already known to be malicious? **Generated**:Flags the submission as known to be malicious, possibly altering its handling.")
    max_extracted = odm.Integer(default=500, description="The maximum number of files that can be extracted from the submission for separate analysis.")
    max_supplementary = odm.Integer(default=500, description="**TODO**: **Original**:Max number of supplementary files **Generated**:The maximum number of supplementary files that can be generated from the submission.")
    priority = odm.Integer(default=1000, description="**TODO**: **Original**:Priority of the scan  **Generated**:The processing priority of the submission, with lower numbers indicating higher priority.")
    profile = odm.Boolean(default=False, description="Triggers additional profiling of the submission for performance and analysis metrics.")
    psid = odm.Optional(odm.UUID(), description="The ID of a parent submission, if this submission is related to an extension of another.")
    quota_item = odm.Boolean(default=False, description="Indicates if this submission should count against the submitter's quota.")
    services = odm.Compound(ServiceSelection, default={}, description="Details which services are selected or excluded from processing this submission.")
    service_spec = odm.Mapping(odm.Mapping(odm.Any()), default={}, index=False, store=False,
                               description="A dictionary specifying service-specific parameters that may alter service behavior for this submission.")
    submitter = odm.Keyword(store=True, copyto="__text__", description="Name of the account that submitted the file for analysis.")
    ttl = odm.Integer(default=0, description="The time-to-live for the submission, defining how many days it will be retained before expiry.")
    type = odm.Keyword(default="USER", description="The type of submission (e.g., `USER` for user-submitted), indicating its origin or purpose.")
    initial_data = odm.Optional(odm.Text(index=False), description="Content provided at the time of submission to initialize the temporary submission data, which may be used during analysis.")
    auto_archive = odm.Boolean(default=False,
                               description="Determines whether the submission should automatically be archived upon completion.")
    delete_after_archive = odm.Boolean(
        default=False,
        description="Specifies if the submission data should be deleted from active storage immediately after archiving.")
    use_archive_alternate_dtl = odm.Boolean(default=False,
                                            description="Indicates if an alternate data lifetime should be applied to the submission once archived.")

    def get_hashing_keys(self):
        """Get the sections of the submission parameters that should be used in result hashes."""
        data = self.as_primitives()
        return {k: v for k, v in data.items() if k in _KEY_HASHED_FIELDS}

    def create_filescore_key(self, sha256, services: list = None):
        """This is the key used to store the final score of a submission for fast lookup.

        This lookup is one of the methods used to check for duplication in ingestion process,
        so this key is fairly sensitive.
        """
        # TODO do we need this version thing still be here?
        # One up this if the cache is ever messed up and we
        # need to quickly invalidate all old cache entries.
        version = 0

        if services is None:
            services = self.services.selected

        data = self.get_hashing_keys()
        data['service_spec'] = sorted((key, sorted(values.items())) for key, values in self.service_spec.items())
        data['sha256'] = sha256
        data['services'] = [str(x) for x in services]

        s = ', '.join([f"{k}: {data[k]}" for k in sorted(data.keys())])

        return 'v'.join([str(hashlib.md5(s.encode()).hexdigest()), str(version)])


@odm.model(index=True, store=True, description="""Captures important timestamps related to the submission's lifecycle, such as when it was submitted and when the analysis was completed.
""")
class Times(odm.Model):
    completed = odm.Optional(odm.Date(store=False), description="Timestamp recording when the analysis of the submission was completed.")
    submitted = odm.Date(default="NOW", description="Timestamp recording when the submission was initiated and began the analysis process.")


@odm.model(index=True, store=False, description="""Reflects the consensus on whether the submission is deemed malicious or non-malicious based on user input.
""")
class Verdict(odm.Model):
    malicious = odm.List(odm.Keyword(), default=[], description="A list of usernames representing users who have judged the submission to be malicious.")
    non_malicious = odm.List(
        odm.Keyword(),
        default=[],
        description="A list of usernames representing users who have judged the submission to be non-malicious.")


@odm.model(index=True, store=True, description="""A Submission in Assemblyline is a critical entity that encapsulates the analysis process and data for a file or collection of files submitted to determine the presence of malware. It contains a wealth of attributes such as file details, parameters for analysis, and the outcome of the scan. Familiarity with the Submission model is essential for users who need to construct precise Lucene search queries. This understanding enables them to effectively navigate and query the Assemblyline system to obtain detailed information on submissions, streamline their search efforts, and efficiently access the desired analysis results.
""")
class Submission(odm.Model):
    archive_ts = odm.Optional(odm.Date(ai=False), description="An optional timestamp indicating when the submission was archived.")
    archived = odm.Boolean(default=False, description="A boolean indicating whether the submission, including the file(s), has been stored in the malware archive.", ai=False)
    classification = odm.Classification(description="Security classification level of the submission.")
    error_count = odm.Integer(description="The total number of errors encountered during the analysis process.", ai=False)
    errors: list[str] = odm.List(odm.Keyword(), store=False, description="A list of error identifiers that were encountered during the analysis process.", ai=False)
    expiry_ts = odm.Optional(odm.Date(store=False), description="An optional timestamp specifying when the submission will expire and be purged from the system.", ai=False)
    file_count = odm.Integer(description="The total number of files included in the submission.", ai=False)
    files: list[File] = odm.List(odm.Compound(File), description="An array of File objects representing the files submitted for analysis, including their names, sizes, and SHA256 hashes.")
    max_score = odm.Integer(description="The highest score assigned to any file within the submission, serving as an indicator of the overall potential threat level of the submission.")
    metadata = odm.FlattenedObject(store=False, description="A flattened object containing additional metadata associated with the submission.")
    params: SubmissionParams = odm.Compound(SubmissionParams, description="Encapsulates the configuration settings and preferences for how the submission is to be processed.", ai=False)
    results: list[str] = odm.List(odm.Keyword(), store=False, description="A list of identifiers for the results generated by the analysis services.", ai=False)
    sid: str = odm.UUID(copyto="__text__", description="The unique identifier (UUID) for the submission, used to track and reference it within the system.")
    state = odm.Enum(values=SUBMISSION_STATES, description="The current status of the submission.", ai=False)
    to_be_deleted = odm.Boolean(
        default=False, description="A boolean flag indicating whether the file(s) associated with the submission are scheduled to be deleted from the system once the analysis is complete.", ai=False)
    times = odm.Compound(Times, default={}, description="An object of type Times that includes timestamps for when the submission was submitted and completed.")
    verdict = odm.Compound(Verdict, default={}, description="Captures user judgments on whether the submission is considered malicious or non-malicious.", ai=False)
    from_archive = odm.Boolean(index=False, default=False, description="A boolean indicating if the submission was loaded from the archive for reanalysis.", ai=False)

    # the filescore key, used in deduplication. This is a non-unique key, that is
    # shared by submissions that may be processed as duplicates.
    scan_key = odm.Optional(odm.Keyword(store=False, index=False, ai=False), description="An optional non-unique identifier known as the filescore key, which is used in the deduplication process. This key may be shared among multiple submissions that contain similar or identical files, thereby allowing Assemblyline to recognize and process them as potential duplicates efficiently.")

    def is_submit(self):
        return self.state == 'submitted'

    def is_complete(self):
        return self.state == 'completed'

    def is_initial(self):
        return self.is_submit() and not self.params.psid

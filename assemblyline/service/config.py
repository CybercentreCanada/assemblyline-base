
from assemblyline.common import version
from assemblyline.common import forge
from assemblyline.remote.datatypes.counters import Counters

config = forge.get_config()
    
#################################################################
# Configuration

CLASSIFICATION = forge.get_classification()

BUILD_MASTER = version.FRAMEWORK_VERSION
BUILD_LOWER = version.SYSTEM_VERSION
BUILD_NO = version.BUILD_MINOR

RATE_LIMITER = Counters(prefix="quota",
                        host=config.core.redis.nonpersistent.host,
                        port=config.core.redis.nonpersistent.port,
                        db=config.core.redis.nonpersistent.db,
                        track_counters=True)

# End of Configuration
#################################################################

#################################################################
# Global instances
STORAGE = forge.get_datastore()

DN_PARSER = forge.get_dn_parser()
# End global
#################################################################

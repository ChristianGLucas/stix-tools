"""Python APIs for STIX 2.

.. autosummary::
   :toctree: api

   confidence
   datastore
   environment
   equivalence
   exceptions
   markings
   parsing
   pattern_visitor
   patterns
   properties
   serialization
   utils
   v20
   v21
   versioning
   workbench

"""

# flake8: noqa

# christiangeorgelucas/stix-tools patch: the upstream import block below also
# pulled in `.datastore.taxii` (TAXIICollectionSink/Source/Store), which
# imports the `requests` package at module scope. `requests` is an
# unconditional (non-extra) install_requires of upstream stix2 purely to
# support this one network-facing TAXII client module, and it transitively
# drags in `certifi` (MPL-2.0) -- copyleft, and disallowed even though this
# package never makes a network call. stix-tools is a stateless, offline
# wrapper (no DataSource/DataSink is ever used), so datastore.taxii and the
# related `workbench` module (which also imports TAXIICollectionSource) are
# simply not vendored -- see vendor/stix2/datastore/taxii.py.removed and
# vendor/stix2/workbench.py.removed for the originals, kept only for
# provenance/diffing, never imported by Python (the .removed extension is not
# a valid module suffix).
from .confidence import scales
from .datastore import CompositeDataSource
from .datastore.filesystem import (
    FileSystemSink, FileSystemSource, FileSystemStore,
)
from .datastore.filters import Filter
from .datastore.memory import MemorySink, MemorySource, MemoryStore
from .environment import Environment, ObjectFactory
from .markings import (
    add_markings, clear_markings, get_markings, is_marked, remove_markings,
    set_markings,
)
from .parsing import parse, parse_observable
from .patterns import (
    AndBooleanExpression, AndObservationExpression, BasicObjectPathComponent,
    BinaryConstant, BooleanConstant, EqualityComparisonExpression,
    FloatConstant, FollowedByObservationExpression,
    GreaterThanComparisonExpression, GreaterThanEqualComparisonExpression,
    HashConstant, HexConstant, InComparisonExpression, IntegerConstant,
    IsSubsetComparisonExpression, IsSupersetComparisonExpression,
    LessThanComparisonExpression, LessThanEqualComparisonExpression,
    LikeComparisonExpression, ListConstant, ListObjectPathComponent,
    MatchesComparisonExpression, ObjectPath, ObservationExpression,
    OrBooleanExpression, OrObservationExpression, ParentheticalExpression,
    QualifiedObservationExpression, ReferenceObjectPathComponent,
    RepeatQualifier, StartStopQualifier, StringConstant, TimestampConstant,
    WithinQualifier,
)
from .registry import _collect_stix2_mappings
from .v21 import *  # This import will always be the latest STIX 2.X version
from .version import DEFAULT_VERSION, __version__
from .versioning import new_version, revoke

_collect_stix2_mappings()

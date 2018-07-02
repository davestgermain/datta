
from msgpack import packb, unpackb
from datetime import datetime
import time
import six
import base64
import uuid
import attr
from datta.ext.subspace import Subspace

if hasattr(datetime, 'fromisoformat'):
    from_isoformat = datetime.fromisoformat
else:
    from dateutil.parser import isoparse as from_isoformat
    

if six.PY2:
    def do_unpack(data):
        return unpackb(data, encoding='utf8', use_list=False)
else:
    def do_unpack(data):
        return unpackb(data, raw=False, use_list=False)

def convert_to_datetime(val):
    if isinstance(val, datetime):
        return val
    if isinstance(val, six.binary_type):
        val = val.decode('utf8')
    if isinstance(val, six.text_type):
        val = from_isoformat(val)
    elif isinstance(val, (int, float)):
        val = datetime.fromtimestamp(val)
    return val

def convert_to_uuid(val):
    if isinstance(val, six.binary_type):
        val = uuid.UUID(bytes=val)
    return val

def convert_to_subspace(val):
    if isinstance(val, six.binary_type):
        val = Subspace(rawPrefix=val)
    return val

def make_record_class(name, fields, version=1):
    if six.PY3:
        # dicts are ordered
        attrs = {}
    else:
        from collections import OrderedDict
        attrs = OrderedDict()
    for fname, ftype in fields:
        if ftype == datetime:
            converter = convert_to_datetime
        elif ftype in (uuid.UUID, 'uuid'):
            converter = convert_to_uuid
            ftype = uuid.UUID
        elif ftype in (Subspace, 'key'):
            converter = convert_to_subspace
            ftype = Subspace
        else:
            converter = None
        attrs[fname] = attr.ib(type=ftype, converter=converter)
    klass = attr.make_class(name, attrs, bases=(Record,))
    klass._version = version
    return klass


@attr.s
class Record(object):
    _version = 1

    def __iter__(self):
        return iter(self.to_tuple())

    def __len__(self):
        return len(self.__attrs_attrs__)

    def __str__(self):
        return base64.b85encode(self.to_bytes()).decode('utf8')

    def get(self, attrname, default=None):
        return getattr(self, attrname, default)

    def pop(self, attrname, default=None):
        val = getattr(self, attrname, None)
        if val is not None:
            setattr(self, attrname, None)
        return val or default

    def update(self, *otherdicts):
        for otherdict in otherdicts:
            for k, v in otherdict.items():
                mine = getattr(self, k, None)
                if mine is None or (v and mine != v):
                    setattr(self, k, v)
    
    def items(self):
        return self.to_dict().items()

    def to_dict(self):
        return attr.asdict(self, recurse=False)

    def to_tuple(self):
        return attr.astuple(self, recurse=False)

    def to_bytes(self):
        to_pack = []
        for field, val in zip(self.__attrs_attrs__, attr.astuple(self, recurse=False)):
            if val is not None:
                if field.type == datetime:
                    val = val.isoformat()
                    if six.PY2:
                        val = val.decode('utf8')
                elif field.type == uuid.UUID:
                    val = val.bytes
                elif field.type == Subspace:
                    val = val.key()
            to_pack.append(val)
        return six.int2byte(self._version) + packb(to_pack, use_bin_type=True)

    __bytes__ = as_foundationdb_value = to_bytes

    @classmethod
    def from_records(cls, *records):
        obj = None
        for rec in records:
            if rec is not None:
                if obj is None:
                    obj = cls.from_dict(rec.to_dict())
                else:
                    obj.update(rec.to_dict())
        return obj

    @classmethod
    def from_tuple(cls, data, version=1):
        return cls(*data)

    @classmethod
    def from_bytes(cls, data):
        version = data[0]
        if not isinstance(version, int):
            version = six.byte2int(version)
        if version > 10:
            # this is an old object, which is actually a dict
            return cls.from_dict(do_unpack(data), version=0)
        else:
            return cls.from_tuple(do_unpack(data[1:]), version)

    @classmethod
    def from_dict(cls, info, version=1):
        args = []
        for field in cls.__attrs_attrs__:
            if field.type in (list, dict, int, tuple):
                default = field.type()
            else:
                default = None
            args.append(info.pop(field.name, default))
        obj = cls(*args)
        obj._extra = info
        return obj

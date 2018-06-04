
from msgpack import packb, unpackb
from datetime import datetime
import time
import six
import base64
import uuid


if six.PY2:
    def to_timestamp(dt):
        if isinstance(dt, datetime):
            return time.mktime(dt.utctimetuple())
        else:
            return dt
    def do_unpack(data):
        return unpackb(data, encoding='utf8', use_list=False)
else:
    def to_timestamp(dt):
        if isinstance(dt, datetime):
            return dt.timestamp()
        else:
            return dt
    def do_unpack(data):
        return unpackb(data, raw=False, use_list=False)


class SlotMaker(type):
    @classmethod
    def make_datetime_prop(cls, attrname):
        def getter(self):
            val = getattr(self, attrname, None)
            if isinstance(val, float):
                val = datetime.utcfromtimestamp(val)
            return val
        def setter(self, dt):
            setattr(self, attrname, to_timestamp(dt))
        def deller(self):
            setattr(self, attrname, None)
        return property(fget=getter, fset=setter, fdel=deller)

    @classmethod
    def make_uuid_prop(cls, attrname):
        def getter(self):
            val = getattr(self, attrname, None)
            if isinstance(val, six.binary_type):
                val = uuid.UUID(byted=val)
            return val
        def setter(self, dt):
            setattr(self, attrname, dt.bytes)
        def deller(self):
            setattr(self, attrname, None)
        return property(fget=getter, fset=setter, fdel=deller)

    def __new__(cls, name, bases, cdict):
        fields = cdict.get('fields', [])
        slots = []
        for field, ftype in fields:
            if ftype == datetime:
                rfield = '_' + field
                cdict[field] = cls.make_datetime_prop(rfield)
                field = rfield
            elif field == uuid.UUID:
                rfield = '_' + field
                cdict[field] = cls.make_uuid_prop(rfield)
                field = rfield
            slots.append(field)
        if not slots:
            slots.append('__dict__')
        cdict['__slots__'] = tuple(slots)
        return super(SlotMaker, cls).__new__(cls, name, bases, cdict)


class Record(metaclass=SlotMaker):
    _version = 1
    if six.PY2:
        __metaclass__ = SlotMaker

    def __init__(self, *args, _version=1, **kwargs):
        if args:
            for v, a in zip(args, self.__slots__):
                setattr(self, a, v)
        elif kwargs:
            for k, v in kwargs.items():
                setattr(self, k, v)

    def __repr__(self):
        return self.__class__.__name__ + repr(self.to_tuple())

    def __len__(self):
        return len(self.__slots__)

    def __str__(self):
        return base64.b85encode(self.to_bytes()).decode('utf8')

    def __setitem__(self, index, val):
        name = self.__slots__[index]
        setattr(self, name, val)

    def __getitem__(self, index):
        return getattr(self, self.__slots__[index], None)

    def get(self, attrname, default=None):
        return getattr(self, attrname, default)

    def pop(self, attrname, default=None):
        val = getattr(self, attrname, None)
        if val is not None:
            setattr(self, attrname, None)
        return val or default

    def update(self, otherdict):
        for k, v in otherdict.items():
            if v is not None:
                setattr(self, k, v)
    
    def items(self):
        return [(k, getattr(self, k, None)) for k in self.__slots__]

    def to_dict(self):
        return {k[0]: getattr(self, k[0], None) for k in self.fields}

    def to_tuple(self):
        return tuple((getattr(self, n, None) for n in self.__slots__))

    def to_bytes(self):
        return bytes(chr(self._version), 'utf8') + packb(self.to_tuple(), use_bin_type=True)

    __bytes__ = as_foundationdb_value = to_bytes

    @classmethod
    def from_tuple(cls, data, version=1):
        obj = cls(*data, _version=version)
        return obj

    @classmethod
    def from_bytes(cls, data):
        version = data[0]
        if version > 10:
            # this is an old object, which is actually a dict
            val = do_unpack(data)
            obj = cls.from_dict(val, version=0)
        else:
            val = do_unpack(data[1:])
            obj = cls.from_tuple(val, version)
        return obj

    @classmethod
    def from_dict(cls, info, version=1):
        obj = cls(_version=version, **info)
        return obj

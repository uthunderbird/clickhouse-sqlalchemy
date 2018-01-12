from sqlalchemy.sql.type_api import to_instance
from sqlalchemy import types


class String(types.String):
    pass


class Int(types.Integer):
    pass


class Float(types.Float):
    pass


class Array(types.TypeEngine):
    __visit_name__ = 'array'

    def __init__(self, item_type):
        self.item_type = item_type
        self.item_type_impl = to_instance(item_type)
        super(Array, self).__init__()

    def literal_processor(self, dialect):
        item_processor = self.item_type_impl.literal_processor(dialect)

        def process(value):
            processed_value = []
            for x in value:
                if item_processor:
                    x = item_processor(x)
                processed_value.append(x)
            return '[' + ', '.join(processed_value) + ']'
        return process


class Nullable(types.TypeEngine):
    __visit_name__ = 'nullable'

    def __init__(self, nested_type):
        self.nested_type = nested_type
        super(Nullable, self).__init__()


class Int8(Int):
    __visit_name__ = 'int8'


class UInt8(Int):
    __visit_name__ = 'uint8'


class Int16(Int):
    __visit_name__ = 'int16'


class UInt16(Int):
    __visit_name__ = 'uint16'


class Int32(Int):
    __visit_name__ = 'int32'


class UInt32(Int):
    __visit_name__ = 'uint32'


class Int64(Int):
    __visit_name__ = 'int64'


class UInt64(Int):
    __visit_name__ = 'uint64'


class Float32(Float):
    __visit_name__ = 'float32'


class Float64(Float):
    __visit_name__ = 'float64'


class Date(types.Date):
    __visit_name__ = 'date'


class DateTime(types.DateTime):
    __visit_name__ = 'datetime'


class Enum8(types.Enum):
    __visit_name__ = 'enum8'

    def __init__(self, *enums, **kw):
        self.enum_type = enums[0]
        super(Enum8, self).__init__(*enums, **kw)


class Enum16(Enum8):
    __visit_name__ = 'enum16'

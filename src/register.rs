pub enum RegisterId {

}

pub enum RegisterType{

}

pub enum RegisterFormat {
    UInt,
    DoubleFloat,
    LongDouble,
    Vector
}

pub struct RegisterInfo {
    id: RegisterId,
    name: String,
    dwarf_id: i32,
    size: usize,
    offset: usize,
    register_type: RegisterType,
    register_format: RegisterFormat,
}

pub const REGISTER_INFO: [RegisterInfo; 0] = [];
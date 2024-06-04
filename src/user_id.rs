#[derive(Clone)]

pub struct UserId {
    name: String,
    id_number: u32,
}

impl UserId{
    pub fn new(name: String, id: u32) -> UserId{
        UserId{
            name: name,
            id_number: id,
        }
    }
    pub fn get_userid_name(self) -> String{
        self.name
    }
    pub fn get_userid_id(self) -> u32{
        self.id_number
    }
}
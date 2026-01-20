use crate::payload::loader::PayloadSet;

pub struct PayloadIterator {
    set: PayloadSet,
    index: usize,
}

impl PayloadIterator {
    pub fn new(set: PayloadSet) -> Self {
        Self { set, index: 0 }
    }
}

impl Iterator for PayloadIterator {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.set.payloads.len() {
            None
        } else {
            let p = self.set.payloads[self.index].clone();
            self.index += 1;
            Some(p)
        }
    }
}

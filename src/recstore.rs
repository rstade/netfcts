use std::fmt;
use std::slice::Iter;
use std::cmp::Ordering;
use std::fmt::Display;
use std::cell::RefCell;
use std::rc::Rc;
use {ConRecord, HasConData, HasTcpState, ReleaseCause};
use TcpState;


pub trait Storable: Sized + Display + Clone {
    fn new() -> Self;
}


pub trait SimpleStore {
    #[inline]
    fn get(&self, slot: usize) -> Option<&ConRecord>;
    fn get_mut(&mut self, slot: usize) -> Option<&mut ConRecord>;
}

pub struct RecordStore<T: Storable> {
    store: Vec<T>,
    used_slots: usize,
}

impl<T: Storable> fmt::Debug for RecordStore<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for i in 0..self.used_slots - 1 {
            write!(f, "{}", self.store[i])?;
        }
        Ok(())
    }
}

impl<T: Storable> RecordStore<T> {
    pub fn with_capacity(capacity: usize) -> RecordStore<T> {
        RecordStore {
            store: vec![T::new(); capacity],
            used_slots: 0,
        }
    }

    #[inline]
    pub fn get_unused_slot(&mut self) -> usize {
        // changed to wrap around
        if self.used_slots >= self.store.len() {
            self.used_slots = 0;
            warn!("wrapping around record storage after exceeding max size = {}", self.store.len());
        }
        self.used_slots += 1;
        self.used_slots - 1
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.used_slots
    }

    #[inline]
    pub fn iter(&self) -> Iter<T> {
        self.store[0..self.used_slots].iter()
    }

    #[inline]
    pub fn get_mut(&mut self, slot: usize) -> Option<&mut T> {
        if slot < self.used_slots {
            Some(&mut self.store[slot])
        } else {
            None
        }
    }

    #[inline]
    pub fn get(&self, slot: usize) -> Option<&T> {
        if slot < self.used_slots {
            Some(&self.store[slot])
        } else {
            None
        }
    }

    pub fn sort_by<F>(&mut self, compare: F)
        where F: FnMut(&T, &T) -> Ordering {
        self.store[0..self.used_slots].sort_by(compare)
    }
}

impl SimpleStore for RecordStore<ConRecord> {
    fn get(&self, slot: usize) -> Option<&ConRecord> {
        if slot < self.used_slots {
            Some(&self.store[slot])
        } else {
            None
        }
    }
    fn get_mut(&mut self, slot: usize) -> Option<&mut ConRecord> {
        if slot < self.used_slots {
            Some(&mut self.store[slot])
        } else {
            None
        }
    }
}

/*
impl Iterator for RecordStore {
    type Item = ConRecord;

    fn next(&mut self) -> Option<Self::Item> {
        self.store.iter().next()
    }
}
*/


pub struct Store64<T: Storable> {
    store_0: Vec<ConRecord>,
    store_1: Vec<T>,
    used_slots: usize,
}

impl<T: Storable> Store64<T> {
    pub fn with_capacity(capacity: usize) -> Store64<T> {
        Store64 {
            store_0: vec![ConRecord::new(); capacity],
            store_1: vec![T::new(); capacity],
            used_slots: 0,
        }
    }

    #[inline]
    pub fn get_unused_slot(&mut self) -> usize {
        // changed to wrap around
        if self.used_slots >= self.store_0.len() || self.used_slots < self.store_1.len() {
            self.used_slots = 0;
            warn!("wrapping around record storage after exceeding max sizes = {}/{}", self.store_0.len(), self.store_1.len());
        }
        self.used_slots += 1;
        self.used_slots - 1
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.used_slots
    }

    #[inline]
    pub fn iter_0(&self) -> Iter<ConRecord> {
        self.store_0[0..self.used_slots].iter()
    }

    #[inline]
    pub fn iter_1(&self) -> Iter<T> {
        self.store_1[0..self.used_slots].iter()
    }

    #[inline]
    pub fn get_mut(&mut self, slot: usize) -> Option<&mut ConRecord> {
        if slot < self.used_slots {
            Some(&mut self.store_0[slot])
        } else {
            None
        }
    }

    #[inline]
    pub fn get(&self, slot: usize) -> Option<&ConRecord> {
        if slot < self.used_slots {
            Some(&self.store_0[slot])
        } else {
            None
        }
    }


    #[inline]
    pub fn get_mut_1(&mut self, slot: usize) -> Option<&mut T> {
        if slot < self.used_slots {
            Some(&mut self.store_1[slot])
        } else {
            None
        }
    }

    #[inline]
    pub fn get_1(&self, slot: usize) -> Option<&T> {
        if slot < self.used_slots {
            Some(&self.store_1[slot])
        } else {
            None
        }
    }

    pub fn sort_0_by<F>(&mut self, compare: F)
        where F: FnMut(&ConRecord, &ConRecord) -> Ordering {
        self.store_0[0..self.used_slots].sort_by(compare)
    }
}

impl<T:Storable> SimpleStore for Store64<T> {
    fn get(&self, slot: usize) -> Option<&ConRecord> {
        if slot < self.used_slots {
            Some(&self.store_0[slot])
        } else {
            None
        }
    }
    fn get_mut(&mut self, slot: usize) -> Option<&mut ConRecord> {
        if slot < self.used_slots {
            Some(&mut self.store_0[slot])
        } else {
            None
        }
    }
}


impl<T: Storable> fmt::Debug for Store64<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for i in 0..self.used_slots - 1 {
            write!(f, "({}, {})", self.store_0[i], self.store_1[i])?;
        }
        Ok(())
    }
}

pub trait ConRecordOperations<S: SimpleStore> {
    /// return reference to reference counted pointer to store for the connection
    #[inline]
    fn store(&self) -> &Rc<RefCell<S>>;

    /// return index of connection record in store
    #[inline]
    fn con_rec(&self) -> usize;

    /// remove references to connection record and its store from connection
    #[inline]
    fn release_conrec(&mut self);

    #[inline]
    fn con_established(&mut self) {
        self.store().borrow_mut().get_mut(self.con_rec()).unwrap().push_state(TcpState::Established);
    }

    #[inline]
    fn server_syn_sent(&mut self) {
        self.store().borrow_mut().get_mut(self.con_rec()).unwrap().push_state(TcpState::SynSent);
        //self.con_rec().s_syn_sent = utils::rdtsc_unsafe();
    }

    #[inline]
    fn port(&self) -> u16 {
        self.store().borrow().get(self.con_rec()).unwrap().port()
    }

    #[inline]
    fn in_use(&self) -> bool;

    #[inline]
    fn server_index(&self) -> usize {
        self.store().borrow().get(self.con_rec()).unwrap().server_index() as usize
    }

    #[inline]
    fn set_server_index(&mut self, index: usize) {
        self.store().borrow_mut().get_mut(self.con_rec()).unwrap().set_server_index(index as u8)
    }

    #[inline]
    fn payload_packets(&self) -> usize {
        self.store().borrow().get(self.con_rec()).unwrap().payload_packets() as usize
    }

    #[inline]
    fn increment_payload_packets(&self) -> usize {
        self.store().borrow_mut().get_mut(self.con_rec()).unwrap().increment_payload_packets() as usize
    }

    #[inline]
    fn last_state(&self) -> TcpState {
        self.store().borrow().get(self.con_rec()).unwrap().last_state()
    }

    #[inline]
    fn states(&self) -> Vec<TcpState> {
        self.store().borrow().get(self.con_rec()).unwrap().states()
    }

    #[inline]
    fn push_state(&self, state: TcpState) {
        self.store().borrow_mut().get_mut(self.con_rec()).unwrap().push_state(state)
    }

    #[inline]
    fn set_release_cause(&self, cause: ReleaseCause) {
        self.store().borrow_mut().get_mut(self.con_rec()).unwrap().set_release_cause(cause)
    }

    #[inline]
    fn set_port(&mut self, port: u16) {
        self.store().borrow_mut().get_mut(self.con_rec()).unwrap().set_port(port);
    }

    #[inline]
    fn sock(&self) -> Option<(u32, u16)> {
        let s = self.store().borrow().get(self.con_rec()).unwrap().sock();
        if s.0 != 0 { Some(s) } else { None }
    }

    #[inline]
    fn set_sock(&mut self, sock: (u32, u16)) {
        self.store().borrow_mut().get_mut(self.con_rec()).unwrap().set_sock(sock);
    }

    #[inline]
    fn set_uid(&mut self, uid: u64) {
        self.store().borrow_mut().get_mut(self.con_rec()).unwrap().set_uid(uid);
    }

    #[inline]
    fn get_uid(&self) -> u64 {
        self.store().borrow().get(self.con_rec()).unwrap().uid()
    }
}
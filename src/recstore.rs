use std::fmt;
use std::slice::Iter;
use std::cmp;
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
    fn get(&self, slot: usize) -> &ConRecord;
    fn get_mut(&mut self, slot: usize) -> &mut ConRecord;
}

pub struct RecordStore<T: Storable> {
    store: Vec<T>,
    record_count: usize,
    overflow_count: usize,
}

impl<T: Storable> fmt::Debug for RecordStore<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for i in 0..self.len() {
            write!(f, "{}\n", self.store[i])?;
        }
        Ok(())
    }
}

impl<T: Storable> RecordStore<T> {
    pub fn with_capacity(capacity: usize) -> RecordStore<T> {
        RecordStore {
            store: vec![T::new(); capacity],
            record_count: 0,
            overflow_count: 0,
        }
    }

    #[inline]
    pub fn get_next_slot(&mut self) -> usize {
        // changed to wrap around
        if self.record_count - self.overflow_count == self.store.len() {
            let wraps = self.record_count / self.store.len();
            warn!("wrapping record storage after exceeding max size = {}, now {} wraps, record_count = {}", self.store.len(), wraps, self.record_count);
            self.overflow_count = self.record_count;
        }
        self.record_count += 1;
        self.record_count - 1
    }

    /// the number of records which are stored (excluding overwritten records)
    #[inline]
    pub fn len(&self) -> usize {
        cmp::min(self.record_count, self.store.len())
    }

    #[inline]
    pub fn iter(&self) -> Iter<T> {
        self.store[0..self.len()].iter()
    }

    pub fn sort_by<F>(&mut self, compare: F)
        where F: FnMut(&T, &T) -> cmp::Ordering {
        let len= self.len();
        self.store[0..len].sort_by(compare)
    }

    #[inline]
    pub fn get(&self, slot: usize) -> &T {
        &self.store[slot - self.overflow_count]
    }

    #[inline]
    pub fn get_mut(&mut self, slot: usize) -> &mut T {
        &mut self.store[slot - self.overflow_count]
    }
}

/// we need trait SimpleStore for the ConRecordOperations trait
impl SimpleStore for RecordStore<ConRecord> {

    #[inline]
    fn get(&self, slot: usize) -> &ConRecord {
        &self.store[slot - self.overflow_count]
    }

    #[inline]
    fn get_mut(&mut self, slot: usize) -> &mut ConRecord {
        &mut self.store[slot - self.overflow_count]
    }
}


pub struct Store64<T: Storable> {
    store_0: Vec<ConRecord>,
    store_1: Vec<T>,
    record_count: usize,
    overflow_count: usize,
}

impl<T: Storable> Store64<T> {
    pub fn with_capacity(capacity: usize) -> Store64<T> {
        Store64 {
            store_0: vec![ConRecord::new(); capacity],
            store_1: vec![T::new(); capacity],
            record_count: 0,
            overflow_count: 0,
        }
    }

    #[inline]
    pub fn get_next_slot(&mut self) -> usize {
        if self.record_count - self.overflow_count == self.store_0.len() {
            let wraps = self.record_count / self.store_0.len();
            warn!("wrapping record storage after exceeding max size = {}, now {} wraps, record_count = {}", self.store_0.len(), wraps, self.record_count);
            self.overflow_count = self.record_count;
        }
        self.record_count += 1;
        self.record_count - 1
    }

    #[inline]
    pub fn len(&self) -> usize {
        cmp::min(self.record_count, self.store_0.len())
    }

    #[inline]
    pub fn iter_0(&self) -> Iter<ConRecord> {
        self.store_0[0..self.len()].iter()
    }

    #[inline]
    pub fn iter_1(&self) -> Iter<T> {
        self.store_1[0..self.len()].iter()
    }

    #[inline]
    pub fn get_mut_1(&mut self, slot: usize) -> &mut T {
        &mut self.store_1[slot - self.overflow_count]
    }

    #[inline]
    pub fn get_1(&self, slot: usize) -> &T {
        &self.store_1[slot - self.overflow_count]
    }

    pub fn sort_0_by<F>(&mut self, compare: F)
        where F: FnMut(&ConRecord, &ConRecord) -> cmp::Ordering {
        let n_records= self.len();
        self.store_0[0..n_records].sort_by(compare)
    }
}

impl<T:Storable> SimpleStore for Store64<T> {

    #[inline]
    fn get(&self, slot: usize) -> &ConRecord {
        &self.store_0[slot - self.overflow_count]
    }

    #[inline]
    fn get_mut(&mut self, slot: usize) -> &mut ConRecord {
        &mut self.store_0[slot - self.overflow_count]
    }

}


impl<T: Storable> fmt::Debug for Store64<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for i in 0..self.len() - 1 {
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
        self.store().borrow_mut().get_mut(self.con_rec()).push_state(TcpState::Established);
    }

    #[inline]
    fn server_syn_sent(&mut self) {
        self.store().borrow_mut().get_mut(self.con_rec()).push_state(TcpState::SynSent);
        //self.con_rec().s_syn_sent = utils::rdtsc_unsafe();
    }

    #[inline]
    fn port(&self) -> u16 {
        self.store().borrow().get(self.con_rec()).port()
    }

    #[inline]
    fn in_use(&self) -> bool;

    #[inline]
    fn server_index(&self) -> usize {
        self.store().borrow().get(self.con_rec()).server_index() as usize
    }

    #[inline]
    fn set_server_index(&mut self, index: usize) {
        self.store().borrow_mut().get_mut(self.con_rec()).set_server_index(index as u8)
    }

    #[inline]
    fn payload_packets(&self) -> usize {
        self.store().borrow().get(self.con_rec()).payload_packets() as usize
    }

    #[inline]
    fn increment_payload_packets(&self) -> usize {
        self.store().borrow_mut().get_mut(self.con_rec()).increment_payload_packets() as usize
    }

    #[inline]
    fn last_state(&self) -> TcpState {
        self.store().borrow().get(self.con_rec()).last_state()
    }

    #[inline]
    fn states(&self) -> Vec<TcpState> {
        self.store().borrow().get(self.con_rec()).states()
    }

    #[inline]
    fn push_state(&self, state: TcpState) {
        self.store().borrow_mut().get_mut(self.con_rec()).push_state(state)
    }

    #[inline]
    fn set_release_cause(&self, cause: ReleaseCause) {
        self.store().borrow_mut().get_mut(self.con_rec()).set_release_cause(cause)
    }

    #[inline]
    fn set_port(&mut self, port: u16) {
        self.store().borrow_mut().get_mut(self.con_rec()).set_port(port);
    }

    #[inline]
    fn sock(&self) -> Option<(u32, u16)> {
        let s = self.store().borrow().get(self.con_rec()).sock();
        if s.0 != 0 { Some(s) } else { None }
    }

    #[inline]
    fn set_sock(&mut self, sock: (u32, u16)) {
        self.store().borrow_mut().get_mut(self.con_rec()).set_sock(sock);
    }

    #[inline]
    fn set_uid(&mut self, uid: u64) {
        self.store().borrow_mut().get_mut(self.con_rec()).set_uid(uid);
    }

    #[inline]
    fn get_uid(&self) -> u64 {
        self.store().borrow().get(self.con_rec()).uid()
    }
}
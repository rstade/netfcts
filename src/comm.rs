use std::fmt;
use std::sync::mpsc::Sender;
use tasks::TaskType;
use tcp_common::TcpCounter;
use uuid::Uuid;
use RecordStore;
use Storable;

#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct PipelineId {
    pub core: u16,
    pub port_id: u16,
    pub rxq: u16,
}

impl fmt::Display for PipelineId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<c{}, p{}, rx{}>", self.core, self.port_id, self.rxq)
    }
}

pub enum MessageFrom<T: Storable> {
    Channel(PipelineId, Sender<MessageTo<T>>),
    StartEngine(Sender<MessageTo<T>>),
    Task(PipelineId, Uuid, TaskType),
    PrintPerformance(Vec<i32>), // performance of tasks on cores selected by indices
    // counter client/to side, counter server/from side, sent_packets with time_stamps
    Counter(PipelineId, TcpCounter, TcpCounter, Option<Vec<(u64, usize, usize)>>),
    CRecords(PipelineId, Option<RecordStore<T>>, Option<RecordStore<T>>), // pipeline_id, client, server
    FetchCounter,                                         // triggers fetching of counters from pipelines
    FetchCRecords,
    Exit, // exit recv thread
}

pub enum MessageTo<T: Storable> {
    FetchCounter, // fetch counters from pipeline
    FetchCRecords,
    Counter(PipelineId, TcpCounter, TcpCounter, Option<Vec<(u64, usize, usize)>>),
    CRecords(PipelineId, Option<RecordStore<T>>, Option<RecordStore<T>>),
    StartGenerator,
    Exit, // exit recv thread
}

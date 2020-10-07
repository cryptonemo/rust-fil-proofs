use filecoin_proofs_v2::types::*;

pub use filecoin_proofs_v2::SectorClass;
/*
#[derive(Clone, Copy, Debug)]
pub struct SectorClass {
    pub sector_size: SectorSize,
    pub partitions: PoRepProofPartitions,
    pub porep_id: [u8; 32],
}

impl From<SectorClass> for PoRepConfig {
    fn from(x: SectorClass) -> Self {
        let SectorClass {
            sector_size,
            partitions,
            porep_id,
        } = x;
        PoRepConfig {
            sector_size,
            partitions,
            porep_id,
        }
    }
}
*/

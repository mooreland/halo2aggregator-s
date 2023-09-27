use super::codegen::SolidityTranscript;
use crate::transcript::sha256::ShaRead;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::pairing::group::ff::PrimeField;
use halo2_proofs::transcript::Challenge255;
use halo2_proofs::transcript::EncodedChallenge;
use halo2_proofs::transcript::Transcript;
use halo2_proofs::transcript::TranscriptRead;
use sha2::Digest;
use std::io;
use std::io::Read;
use std::marker::PhantomData;

#[derive(Debug, Clone)]
pub struct SolidityShaRead<C: CurveAffine, E: EncodedChallenge<C>> {
    _phantom: PhantomData<(C, E)>,
}

impl<C: CurveAffine, E: EncodedChallenge<C>> SolidityShaRead<C, E> {
    pub fn init() -> Self {
        SolidityShaRead::<C, E> {
            _phantom: PhantomData,
        }
    }
}

impl<C: CurveAffine> TranscriptRead<C, Challenge255<C>> for SolidityShaRead<C, Challenge255<C>> {
    fn read_point(&mut self) -> io::Result<C> {
        Ok(C::identity())
    }

    fn read_scalar(&mut self) -> io::Result<C::Scalar> {
        Ok(C::Scalar::root_of_unity())
    }
}

impl<C: CurveAffine> Transcript<C, Challenge255<C>> for SolidityShaRead<C, Challenge255<C>> {
    fn squeeze_challenge(&mut self) -> Challenge255<C> {
        let mut bytes = vec![];
        bytes.resize(64, 0u8);

        Challenge255::<C>::new(&bytes.try_into().unwrap())
    }

    fn common_point(&mut self, _point: C) -> io::Result<()> {
        Ok(())
    }

    fn common_scalar(&mut self, _scalar: C::Scalar) -> io::Result<()> {
        Ok(())
    }
}

impl<C: CurveAffine> SolidityTranscript<C> for SolidityShaRead<C, Challenge255<C>> {}

pub enum SolidityShaSelector<R: Read, C: CurveAffine, D: Digest> {
    ShaRead(ShaRead<R, C, Challenge255<C>, D>),
    SolidityShaRead(SolidityShaRead<C, Challenge255<C>>),
}

impl<R: Read, C: CurveAffine, D: Digest + Clone> TranscriptRead<C, Challenge255<C>>
    for SolidityShaSelector<R, C, D>
{
    fn read_point(&mut self) -> io::Result<C> {
        match self {
            SolidityShaSelector::ShaRead(hasher) => hasher.read_point(),
            SolidityShaSelector::SolidityShaRead(hasher) => hasher.read_point(),
        }
    }

    fn read_scalar(&mut self) -> io::Result<C::Scalar> {
        match self {
            SolidityShaSelector::ShaRead(hasher) => hasher.read_scalar(),
            SolidityShaSelector::SolidityShaRead(hasher) => hasher.read_scalar(),
        }
    }
}

impl<R: Read, C: CurveAffine, D: Digest + Clone> Transcript<C, Challenge255<C>>
    for SolidityShaSelector<R, C, D>
{
    fn squeeze_challenge(&mut self) -> Challenge255<C> {
        match self {
            SolidityShaSelector::ShaRead(hasher) => hasher.squeeze_challenge(),
            SolidityShaSelector::SolidityShaRead(hasher) => hasher.squeeze_challenge(),
        }
    }

    fn common_point(&mut self, point: C) -> io::Result<()> {
        match self {
            SolidityShaSelector::ShaRead(hasher) => hasher.common_point(point),
            SolidityShaSelector::SolidityShaRead(hasher) => hasher.common_point(point),
        }
    }

    fn common_scalar(&mut self, scalar: <C>::Scalar) -> io::Result<()> {
        match self {
            SolidityShaSelector::ShaRead(hasher) => hasher.common_scalar(scalar),
            SolidityShaSelector::SolidityShaRead(hasher) => hasher.common_scalar(scalar),
        }
    }
}

impl<R: Read, C: CurveAffine, D: Digest + Clone> SolidityTranscript<C>
    for SolidityShaSelector<R, C, D>
{
}

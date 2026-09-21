//! Serialization for the custom gates and witness generators used by ECDSA.

use alloc::{format, string::String, vec::Vec};
use core::{any::type_name, marker::PhantomData};

use plonky2::field::{
    extension::Extendable, secp256k1_base::Secp256K1Base, secp256k1_scalar::Secp256K1Scalar,
};
use plonky2::gates::{
    base_sum::{BaseSplitGenerator, BaseSumGate},
    gate::{Gate, GateRef},
};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::generator::{SimpleGenerator, WitnessGeneratorRef};
use plonky2::plonk::{
    circuit_data::CommonCircuitData,
    config::{AlgebraicHasher, GenericConfig},
};
use plonky2::util::serialization::{
    Buffer, GateSerializer, IoError, IoResult, Read, WitnessGeneratorSerializer, Write,
};
use plonky2_u32::gates::{
    add_many_u32::U32AddManyGate,
    arithmetic_u32::{U32GateSerializer, U32GeneratorSerializer},
    comparison::ComparisonGate,
    range_check_u32::U32RangeCheckGate,
    subtraction_u32::U32SubtractionGate,
};

use crate::gadgets::{
    biguint::BigUintDivRemGenerator,
    glv::GLVDecompositionGenerator,
    nonnative::{
        NonNativeAdditionGenerator, NonNativeInverseGenerator, NonNativeMultipleAddsGenerator,
        NonNativeMultiplicationGenerator, NonNativeSubtractionGenerator,
    },
};

/// Gate serializer for the pinned `plonky2_u32` revision plus its omitted gates.
#[derive(Debug)]
pub struct EcdsaGateSerializer;

impl<F: RichField + Extendable<D>, const D: usize> GateSerializer<F, D> for EcdsaGateSerializer {
    fn read_gate(
        &self,
        src: &mut Buffer,
        common: &CommonCircuitData<F, D>,
    ) -> IoResult<GateRef<F, D>> {
        Ok(match src.read_u32()? {
            0 => return U32GateSerializer.read_gate(src, common),
            1 => GateRef::new(U32AddManyGate::<F, D>::deserialize(src, common)?),
            2 => GateRef::new(U32SubtractionGate::<F, D>::deserialize(src, common)?),
            3 => GateRef::new(ComparisonGate::<F, D>::deserialize(src, common)?),
            4 => GateRef::new(U32RangeCheckGate::<F, D>::deserialize(src, common)?),
            5 => GateRef::new(BaseSumGate::<4>::deserialize(src, common)?),
            _ => return Err(IoError),
        })
    }

    fn write_gate(
        &self,
        dst: &mut Vec<u8>,
        gate: &GateRef<F, D>,
        common: &CommonCircuitData<F, D>,
    ) -> IoResult<()> {
        let any = gate.0.as_any();
        let tag = if any.is::<U32AddManyGate<F, D>>() {
            1
        } else if any.is::<U32SubtractionGate<F, D>>() {
            2
        } else if any.is::<ComparisonGate<F, D>>() {
            3
        } else if any.is::<U32RangeCheckGate<F, D>>() {
            4
        } else if any.is::<BaseSumGate<4>>() {
            5
        } else {
            dst.write_u32(0)?;
            return U32GateSerializer.write_gate(dst, gate, common);
        };
        dst.write_u32(tag)?;
        gate.0.serialize(dst, common)
    }
}

/// Generator serializer for ECDSA and the pinned `plonky2_u32@fcabb02` format.
///
/// Three u32 generator types are private and absent from that revision's
/// serializer. Their own serialization stores a public gate plus row/index, so
/// deserialization reconstructs the unchanged generator through `Gate::generators`.
#[derive(Debug, Default)]
pub struct EcdsaGeneratorSerializer<C: GenericConfig<D>, const D: usize> {
    _phantom: PhantomData<C>,
}

impl<F, C, const D: usize> WitnessGeneratorSerializer<F, D> for EcdsaGeneratorSerializer<C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    fn read_generator(
        &self,
        src: &mut Buffer,
        common: &CommonCircuitData<F, D>,
    ) -> IoResult<WitnessGeneratorRef<F, D>> {
        macro_rules! read {
            ($ty:ty) => {{
                let generator = <$ty as SimpleGenerator<F, D>>::deserialize(src, common)?;
                WitnessGeneratorRef::new(generator.adapter())
            }};
        }

        Ok(match src.read_u32()? {
            0 => {
                let serializer = U32GeneratorSerializer::<C, D> {
                    _phantom: PhantomData,
                };
                return serializer.read_generator(src, common);
            }
            1 => read!(BigUintDivRemGenerator<F, D>),
            2 => read!(GLVDecompositionGenerator<F, D>),
            3 => read!(NonNativeAdditionGenerator<F, D, Secp256K1Scalar>),
            4 => read!(NonNativeMultipleAddsGenerator<F, D, Secp256K1Scalar>),
            5 => read!(NonNativeSubtractionGenerator<F, D, Secp256K1Scalar>),
            6 => read!(NonNativeMultiplicationGenerator<F, D, Secp256K1Scalar>),
            7 => read!(NonNativeInverseGenerator<F, D, Secp256K1Scalar>),
            8 => read!(NonNativeAdditionGenerator<F, D, Secp256K1Base>),
            9 => read!(NonNativeMultipleAddsGenerator<F, D, Secp256K1Base>),
            10 => read!(NonNativeSubtractionGenerator<F, D, Secp256K1Base>),
            11 => read!(NonNativeMultiplicationGenerator<F, D, Secp256K1Base>),
            12 => read!(NonNativeInverseGenerator<F, D, Secp256K1Base>),
            13 => read_gate_generator::<F, D, U32AddManyGate<F, D>>(src, common, true)?,
            14 => read_gate_generator::<F, D, U32SubtractionGate<F, D>>(src, common, true)?,
            15 => {
                let row = src.read_usize()?;
                let gate = ComparisonGate::<F, D>::deserialize(src, common)?;
                gate.generators(row, &[])
                    .into_iter()
                    .next()
                    .ok_or(IoError)?
            }
            16 => read_gate_generator::<F, D, U32RangeCheckGate<F, D>>(src, common, false)?,
            17 => read!(BaseSplitGenerator<4>),
            _ => return Err(IoError),
        })
    }

    fn write_generator(
        &self,
        dst: &mut Vec<u8>,
        generator: &WitnessGeneratorRef<F, D>,
        common: &CommonCircuitData<F, D>,
    ) -> IoResult<()> {
        let id = generator.0.id();
        let tag = generator_tag::<Secp256K1Scalar, Secp256K1Base>(&id);
        if let Some(tag) = tag {
            dst.write_u32(tag)?;
            generator.0.serialize(dst, common)
        } else {
            dst.write_u32(0)?;
            U32GeneratorSerializer::<C, D> {
                _phantom: PhantomData,
            }
            .write_generator(dst, generator, common)
        }
    }
}

fn read_gate_generator<F, const D: usize, G>(
    src: &mut Buffer,
    common: &CommonCircuitData<F, D>,
    has_index: bool,
) -> IoResult<WitnessGeneratorRef<F, D>>
where
    F: RichField + Extendable<D>,
    G: Gate<F, D>,
{
    let gate = G::deserialize(src, common)?;
    let row = src.read_usize()?;
    let index = if has_index { src.read_usize()? } else { 0 };
    gate.generators(row, &[])
        .into_iter()
        .nth(index)
        .ok_or(IoError)
}

fn generator_tag<S, B>(id: &str) -> Option<u32> {
    let typed = |name: &str, ty: &str| -> String { format!("{name}<{ty}>") };
    match id {
        "BigUintDivRemGenerator" => Some(1),
        "GLVDecompositionGenerator" => Some(2),
        "U32AddManyGenerator" => Some(13),
        "U32SubtractionGenerator" => Some(14),
        "ComparisonGenerator" => Some(15),
        "U32RangeCheckGenerator" => Some(16),
        "BaseSplitGenerator + Base: 4" => Some(17),
        _ if id == typed("NonNativeAdditionGenerator", type_name::<S>()) => Some(3),
        _ if id == typed("NonNativeMultipleAddsGenerator", type_name::<S>()) => Some(4),
        _ if id == typed("NonNativeSubtractionGenerator", type_name::<S>()) => Some(5),
        _ if id == typed("NonNativeMultiplicationGenerator", type_name::<S>()) => Some(6),
        _ if id == typed("NonNativeInverseGenerator", type_name::<S>()) => Some(7),
        _ if id == typed("NonNativeAdditionGenerator", type_name::<B>()) => Some(8),
        _ if id == typed("NonNativeMultipleAddsGenerator", type_name::<B>()) => Some(9),
        _ if id == typed("NonNativeSubtractionGenerator", type_name::<B>()) => Some(10),
        _ if id == typed("NonNativeMultiplicationGenerator", type_name::<B>()) => Some(11),
        _ if id == typed("NonNativeInverseGenerator", type_name::<B>()) => Some(12),
        _ => None,
    }
}

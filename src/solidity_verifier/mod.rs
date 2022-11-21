use self::codegen::solidity_codegen_with_proof;
use halo2_proofs::arithmetic::BaseExt;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2ecc_s::utils::field_to_bn;
use num_bigint::BigUint;
use tera::Tera;

pub mod codegen;

pub fn solidity_render<E: MultiMillerLoop>(
    path_in: &str,
    path_out: &str,
    template_name: &str,
    target_circuit_params: &ParamsVerifier<E>,
    verify_circuit_params: &ParamsVerifier<E>,
    vkey: &VerifyingKey<E::G1Affine>,
    instances: &Vec<E::Scalar>,
    proofs: Vec<u8>,
) {
    let tera = Tera::new(path_in).unwrap();
    let mut tera_ctx = tera::Context::new();

    let g2field_to_bn = |f: &<E::G2Affine as CurveAffine>::Base| {
        let mut bytes: Vec<u8> = Vec::new();
        f.write(&mut bytes).unwrap();
        (
            BigUint::from_bytes_le(&bytes[32..64]),
            BigUint::from_bytes_le(&bytes[..32]),
        )
    };

    let insert_g2 = |tera_ctx: &mut tera::Context, prefix, g2: E::G2Affine| {
        let c = g2.coordinates().unwrap();
        let x = g2field_to_bn(c.x());
        let y = g2field_to_bn(c.y());
        tera_ctx.insert(format!("{}_{}", prefix, "x0"), &x.0.to_str_radix(10));
        tera_ctx.insert(format!("{}_{}", prefix, "x1"), &x.1.to_str_radix(10));
        tera_ctx.insert(format!("{}_{}", prefix, "y0"), &y.0.to_str_radix(10));
        tera_ctx.insert(format!("{}_{}", prefix, "y1"), &y.1.to_str_radix(10));
    };

    insert_g2(
        &mut tera_ctx,
        "target_circuit_s_g2",
        target_circuit_params.s_g2,
    );
    insert_g2(
        &mut tera_ctx,
        "target_circuit_n_g2",
        -target_circuit_params.g2,
    );
    insert_g2(
        &mut tera_ctx,
        "verify_circuit_s_g2",
        verify_circuit_params.s_g2,
    );
    insert_g2(
        &mut tera_ctx,
        "verify_circuit_n_g2",
        -verify_circuit_params.g2,
    );

    let verify_circuit_g_lagrange = verify_circuit_params
        .g_lagrange
        .iter()
        .map(|g1| {
            let c = g1.coordinates().unwrap();
            [
                field_to_bn(c.x()).to_str_radix(10),
                field_to_bn(c.y()).to_str_radix(10),
            ]
        })
        .collect::<Vec<_>>();
    tera_ctx.insert(
        "verify_circuit_lagrange_commitments",
        &verify_circuit_g_lagrange,
    );

    let target_circuit_g_lagrange = target_circuit_params
        .g_lagrange
        .iter()
        .map(|g1| {
            let c = g1.coordinates().unwrap();
            [
                field_to_bn(c.x()).to_str_radix(10),
                field_to_bn(c.y()).to_str_radix(10),
            ]
        })
        .collect::<Vec<_>>();
    tera_ctx.insert(
        "target_circuit_lagrange_commitments",
        &target_circuit_g_lagrange,
    );

    // vars for challenge

    let mut hasher = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(b"Halo2-Verify-Key")
        .to_state();

    let s = format!("{:?}", vkey.pinned());
    hasher.update(&(s.len() as u64).to_le_bytes());
    hasher.update(s.as_bytes());

    let scalar = E::Scalar::from_bytes_wide(hasher.finalize().as_array());

    tera_ctx.insert("init_scalar", &field_to_bn(&scalar).to_str_radix(10));

    tera_ctx.insert("n_advice", &vkey.cs.num_advice_columns);

    let lookups = vkey.cs.lookups.len();
    tera_ctx.insert("lookups", &lookups);

    let n_permutation_product = vkey
        .cs
        .permutation
        .columns
        .chunks(vkey.cs.degree() - 2)
        .len();
    tera_ctx.insert("permutation_products", &n_permutation_product);

    tera_ctx.insert("degree", &vkey.domain.get_quotient_poly_degree());

    let evals = vkey.cs.instance_queries.len()
        + vkey.cs.advice_queries.len()
        + vkey.cs.fixed_queries.len()
        + 1
        + vkey.permutation.commitments.len()
        + 3 * n_permutation_product
        - 1
        + 5 * lookups;
    tera_ctx.insert("evals", &evals);

    solidity_codegen_with_proof(
        &verify_circuit_params,
        &vkey,
        instances,
        proofs,
        &mut tera_ctx,
    );

    let fd = std::fs::File::create(path_out).unwrap();

    tera.render_to(template_name, &tera_ctx, fd)
        .expect("failed to render template");
}

#[test]
pub fn test_solidity_render() {
    use crate::circuits::samples::simple::SimpleCircuit;
    use crate::circuits::utils::load_or_build_unsafe_params;
    use crate::circuits::utils::load_or_build_vkey;
    use crate::circuits::utils::load_proof;
    use crate::circuits::utils::run_circuit_unsafe_full_pass;
    use crate::circuits::utils::TranscriptHash;
    use crate::solidity_verifier::codegen::solidity_aux_gen;
    use halo2_proofs::pairing::bn256::Bn256;
    use halo2_proofs::pairing::bn256::Fr;
    use halo2_proofs::plonk::Circuit;
    use std::fs::DirBuilder;
    use std::path::Path;

    let path = "./output";
    DirBuilder::new().recursive(true).create(path).unwrap();

    let n_proofs = 2;
    let target_circuit_k = 8;
    let verify_circuit_k = 21;

    let path = Path::new(path);
    let (circuit, instances) = SimpleCircuit::<Fr>::random_new_with_instance();
    let (circuit, instances) = run_circuit_unsafe_full_pass::<Bn256, _>(
        path,
        "simple-circuit",
        target_circuit_k,
        vec![circuit.clone(), circuit],
        vec![instances.clone(), instances],
        TranscriptHash::Poseidon,
        vec![],
        true,
    )
    .unwrap();

    let circuit0 = circuit.without_witnesses();
    run_circuit_unsafe_full_pass::<Bn256, _>(
        path,
        "verify-circuit",
        verify_circuit_k,
        vec![circuit],
        vec![vec![instances.clone()]],
        TranscriptHash::Sha,
        vec![],
        true,
    );

    let params = load_or_build_unsafe_params::<Bn256>(
        target_circuit_k,
        Some(&path.join(format!("K{}.params", target_circuit_k))),
    );
    let target_params_verifier: ParamsVerifier<Bn256> = params.verifier(1).unwrap();

    let params = load_or_build_unsafe_params::<Bn256>(
        verify_circuit_k,
        Some(&path.join(format!("K{}.params", verify_circuit_k))),
    );
    let verifier_params_verifier: ParamsVerifier<Bn256> =
        params.verifier(6 + 3 * n_proofs).unwrap();

    let vkey = load_or_build_vkey::<Bn256, _>(
        &params,
        &circuit0,
        Some(&path.join(format!("{}.{}.vkey.data", "verify-circuit", 0))),
    );

    let proof = load_proof(&path.join(format!("{}.{}.transcript.data", "verify-circuit", 0)));

    solidity_render(
        "sol/templates/*",
        "sol/contracts/AggregatorConfig.sol",
        "AggregatorConfig.sol.tera",
        &target_params_verifier,
        &verifier_params_verifier,
        &vkey,
        &instances,
        proof.clone(),
    );

    solidity_aux_gen(
        &verifier_params_verifier,
        &vkey,
        &instances,
        proof,
        &path.join(format!("{}.{}.aux.data", "verify-circuit", 0)),
    );
}

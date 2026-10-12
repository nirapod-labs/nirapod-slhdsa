(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * SPHINCS_Sets.ec
 * ===============
 *
 * The EUF-CMA theorem of SLHDSA_EUFCMA for each parameter set of FIPS 205
 * Table 2: SLH_DSA_<SET>.slhdsa_euf_cma. Each clone discharges the one
 * assumption of the abstract theory, that P is a row of the table, so
 * every result of SPHINCS_Instance, SPHINCS_Refinement and SLHDSA_EUFCMA
 * holds for every set.
 *)

require import List FIPS205_Params.
require SLHDSA_EUFCMA.

clone SLHDSA_EUFCMA as SLH_DSA_SHA2_128S with op P <- slh_dsa_sha2_128s proof *.
realize P_in by rewrite /parameter_sets.

clone SLHDSA_EUFCMA as SLH_DSA_SHAKE_128S with op P <- slh_dsa_shake_128s proof *.
realize P_in by rewrite /parameter_sets.

clone SLHDSA_EUFCMA as SLH_DSA_SHA2_128F with op P <- slh_dsa_sha2_128f proof *.
realize P_in by rewrite /parameter_sets.

clone SLHDSA_EUFCMA as SLH_DSA_SHAKE_128F with op P <- slh_dsa_shake_128f proof *.
realize P_in by rewrite /parameter_sets.

clone SLHDSA_EUFCMA as SLH_DSA_SHA2_192S with op P <- slh_dsa_sha2_192s proof *.
realize P_in by rewrite /parameter_sets.

clone SLHDSA_EUFCMA as SLH_DSA_SHAKE_192S with op P <- slh_dsa_shake_192s proof *.
realize P_in by rewrite /parameter_sets.

clone SLHDSA_EUFCMA as SLH_DSA_SHA2_192F with op P <- slh_dsa_sha2_192f proof *.
realize P_in by rewrite /parameter_sets.

clone SLHDSA_EUFCMA as SLH_DSA_SHAKE_192F with op P <- slh_dsa_shake_192f proof *.
realize P_in by rewrite /parameter_sets.

clone SLHDSA_EUFCMA as SLH_DSA_SHA2_256S with op P <- slh_dsa_sha2_256s proof *.
realize P_in by rewrite /parameter_sets.

clone SLHDSA_EUFCMA as SLH_DSA_SHAKE_256S with op P <- slh_dsa_shake_256s proof *.
realize P_in by rewrite /parameter_sets.

clone SLHDSA_EUFCMA as SLH_DSA_SHA2_256F with op P <- slh_dsa_sha2_256f proof *.
realize P_in by rewrite /parameter_sets.

clone SLHDSA_EUFCMA as SLH_DSA_SHAKE_256F with op P <- slh_dsa_shake_256f proof *.
realize P_in by rewrite /parameter_sets.

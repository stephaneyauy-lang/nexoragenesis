# Compilateur en Nova — index des responsabilités

Les imports utilisent des noms de modules, pas la catégorie du dossier. Le backend MIR C fournit une liste explicite de fichiers ; elle a été adaptée à cette organisation. Les tests et les entrées de test résident dans `../../tests/nova/`.

## frontend

Lexique, AST, parseur, déclarations et résolution des noms.

| Fichier | Module déclaré | Points publics (extrait) |
|---|---|---|
| [ast.nova](frontend/ast.nova) | `ntasm_ast` | `Tree`, `Node`, `node_at`, `node_kind`, `node_token_begin` |
| [bindings.nova](frontend/bindings.nova) | `bindings` | `check` |
| [decls.nova](frontend/decls.nova) | `decls` | `collect` |
| [lexer.nova](frontend/lexer.nova) | `ntasm_lexer` | `Span`, `Token`, `Diagnostic`, `Result`, `lex` |
| [locals.nova](frontend/locals.nova) | `locals` | `check` |
| [nova_language_lex.nova](frontend/nova_language_lex.nova) | `nova_language_lex` | `let`, `keyword_words`, `keyword_read_back`, `scan` |
| [nova_language_parse.nova](frontend/nova_language_parse.nova) | `nova_language_parse` | `NODE_WORDS`, `K_MODULE`, `K_IMPORT`, `K_STRUCT`, `K_FIELD` |
| [nova_source_emit.nova](frontend/nova_source_emit.nova) | `nova_source_emit` | `emit` |
| [parameters.nova](frontend/parameters.nova) | `parameters` | `check` |
| [parser.nova](frontend/parser.nova) | `ntasm_parser` | `keyword_words`, `keyword_read_back`, `parse` |
| [refs.nova](frontend/refs.nova) | `ntasm_refs` | `resolve` |
| [register_bindings.nova](frontend/register_bindings.nova) | `register_bindings` | `check` |
| [stub_table.nova](frontend/stub_table.nova) | `stub_table` | `check`, `measure`, `plan_for`, `lower`, `build_pe` |
| [symbol_names.nova](frontend/symbol_names.nova) | `symbol_names` | `check` |
| [targets.nova](frontend/targets.nova) | `targets` | `check` |
| [versions.nova](frontend/versions.nova) | `versions` | `check` |

## analysis

Validation sémantique, flot de contrôle et diagnostics.

| Fichier | Module déclaré | Points publics (extrait) |
|---|---|---|
| [c_conversion.nova](analysis/c_conversion.nova) | `c_conversion` | `C_TYPE_WORDS`, `C_TYPE_KIND`, `C_TYPE_SPACE`, `C_TYPE_ELEMENT`, `C_TYPE_COUNT` |
| [control_flow.nova](analysis/control_flow.nova) | `control_flow` | `abi_ceiling`, `writes_stack`, `replaces_stack`, `displaces_stack`, `statement_writes_stack` |
| [diagnostics.nova](analysis/diagnostics.nova) | `diagnostics` | `capacity`, `entry_words`, `probe_capacity`, `resync_budget`, `slice_passes` |
| [semantics.nova](analysis/semantics.nova) | `semantics` | `index` |
| [validate.nova](analysis/validate.nova) | `validate` | `stage_table`, `validate`, `spliced_shape`, `validate_expanded` |

## analysis/abi

ABI, contrats, effets, registres modifiés et exigences CPU.

| Fichier | Module déclaré | Points publics (extrait) |
|---|---|---|
| [abi.nova](analysis/abi/abi.nova) | `abi` | `direction`, `parameter_mode`, `parameter_rules`, `check`, `declaration_at` |
| [body_clobbers.nova](analysis/abi/body_clobbers.nova) | `body_clobbers` | `check` |
| [body_effects.nova](analysis/abi/body_effects.nova) | `body_effects` | `check` |
| [body_intrinsics.nova](analysis/abi/body_intrinsics.nova) | `body_intrinsics` | `check` |
| [clobbers.nova](analysis/abi/clobbers.nova) | `clobbers` | `check`, `summarize` |
| [contracts.nova](analysis/abi/contracts.nova) | `contracts` | `check` |
| [effects.nova](analysis/abi/effects.nova) | `effects` | `atom_of`, `memory_of`, `space_of`, `summarize`, `check` |
| [feature_requirements.nova](analysis/abi/feature_requirements.nova) | `feature_requirements` | `check` |
| [features.nova](analysis/abi/features.nova) | `features` | `lookup`, `check` |

## analysis/calls

Résolution des appels, arguments et contrats des fonctions appelées.

| Fichier | Module déclaré | Points publics (extrait) |
|---|---|---|
| [call_clobbers.nova](analysis/calls/call_clobbers.nova) | `call_clobbers` | `check` |
| [call_contracts.nova](analysis/calls/call_contracts.nova) | `call_contracts` | `check` |
| [call_effects.nova](analysis/calls/call_effects.nova) | `call_effects` | `check` |
| [call_types.nova](analysis/calls/call_types.nova) | `call_types` | `check` |
| [callable_names.nova](analysis/calls/callable_names.nova) | `callable_names` | `check` |
| [calls.nova](analysis/calls/calls.nova) | `calls` | `check` |

## analysis/types

Types, largeurs, initialisations, retours et espaces mémoire.

| Fichier | Module déclaré | Points publics (extrait) |
|---|---|---|
| [condition_types.nova](analysis/types/condition_types.nova) | `condition_types` | `check` |
| [constant_types.nova](analysis/types/constant_types.nova) | `constant_types` | `check` |
| [initializer_types.nova](analysis/types/initializer_types.nova) | `initializer_types` | `visible_type_id`, `visible_type_at`, `register_bits`, `declared_bits`, `integer_status` |
| [literal_initializers.nova](analysis/types/literal_initializers.nova) | `literal_initializers` | `check` |
| [pointer_spaces.nova](analysis/types/pointer_spaces.nova) | `pointer_spaces` | `check` |
| [register_widths.nova](analysis/types/register_widths.nova) | `register_widths` | `width`, `family`, `clobber_bit`, `check` |
| [return_types.nova](analysis/types/return_types.nova) | `return_types` | `check` |
| [types.nova](analysis/types/types.nova) | `types` | `check` |

## macros

Expansion AST, insertion et évaluation constante.

| Fichier | Module déclaré | Points publics (extrait) |
|---|---|---|
| [constant_eval.nova](macros/constant_eval.nova) | `constant_eval` | `Value`, `evaluate` |
| [macro_expand.nova](macros/macro_expand.nova) | `ntasm_macro_expand` | `expand`, `measure` |
| [macro_splice.nova](macros/macro_splice.nova) | `ntasm_macro_splice` | `Splice`, `blank_splice`, `splice_release`, `unit_of`, `expand_stage` |

## ir

Construction et validation des représentations intermédiaires.

| Fichier | Module déclaré | Points publics (extrait) |
|---|---|---|
| [ir_image.nova](ir/ir_image.nova) | `ir_image` | `ReadResult`, `FORMAT_VERSION`, `HEADER_BYTES`, `WORD_BYTES`, `TAG_LENGTH` |
| [machine_ir.nova](ir/machine_ir.nova) | `machine_ir` | `FORMAT_MAJOR`, `FORMAT_MINOR`, `HEADER_WORDS`, `NODE_WORDS`, `KIND_BASE` |
| [machine_pipeline.nova](ir/machine_pipeline.nova) | `machine_pipeline` | `E_OUTPUT`, `E_BOUND`, `STAGE_PARSE`, `STAGE_EXPAND`, `STAGE_VALIDATE` |

## backend/nova

Abaissement de Nova et construction par lots.

| Fichier | Module déclaré | Points publics (extrait) |
|---|---|---|
| [machine_emit.nova](backend/nova/machine_emit.nova) | `machine_emit` | `E_IMAGE`, `E_FORM`, `E_CALL`, `E_CONTRACT`, `E_LAYOUT` |
| [nova_machine_abi2.nova](backend/nova/nova_machine_abi2.nova) | `nova_machine_abi2` | `lower_abi2` |
| [nova_machine_batches.nova](backend/nova/nova_machine_batches.nova) | `nova_machine_batches` | `MAX_OBJECTS`, `HEADER_BYTES`, `MAX_OBJECT_BYTES`, `build_objects`, `build_objects_progress` |
| [nova_machine_lower.nova](backend/nova/nova_machine_lower.nova) | `nova_machine_lower` | `E_UNSUPPORTED`, `E_AST`, `E_BOUND`, `E_ROOT`, `main` |
| [nova_machine_many.nova](backend/nova/nova_machine_many.nova) | `nova_machine_many` | `lower_many`, `lower_many_closed`, `lower_many_batch` |

## backend/x64

Encodages et abaissements vers x86-64.

| Fichier | Module déclaré | Points publics (extrait) |
|---|---|---|
| [machine_x64.nova](backend/x64/machine_x64.nova) | `machine_x64` | `E_IMAGE`, `E_OPCODE`, `E_FORM`, `E_REGISTER`, `E_CALL` |
| [x64_fixed.nova](backend/x64/x64_fixed.nova) | `x64_fixed` | `encode`, `encode_rr`, `encode_ri`, `encode_unary`, `encode_shift_imm` |
| [x64_lower_control.nova](backend/x64/x64_lower_control.nova) | `x64_lower_control` | `lower_wide`, `lower_wide_range`, `branch_length`, `branch_target_id`, `lower` |
| [x64_lower_fixed.nova](backend/x64/x64_lower_fixed.nova) | `x64_lower_fixed` | `signed_scalar_width`, `memory_element_width`, `encode_instruction`, `lower` |
| [x64_lower_nxo.nova](backend/x64/x64_lower_nxo.nova) | `x64_lower_nxo` | `call_fold`, `build`, `f`, `build_scalar_data`, `build_import_call` |
| [x64_lower_nxo_pe.nova](backend/x64/x64_lower_nxo_pe.nova) | `x64_lower_nxo_pe` | `build`, `build_local_helper_call`, `build_local_helper_call_with_scalar_data`, `build_local_helper_calls`, `build_local_helper_calls_with_scalar_data` |

## formats/ntir

Représentation NTIR.

| Fichier | Module déclaré | Points publics (extrait) |
|---|---|---|
| [ntir.nova](formats/ntir/ntir.nova) | `ntir` | `FORMAT_MAJOR`, `FORMAT_MINOR`, `KIND_BASE`, `HEADER_WORDS`, `NODE_WORDS` |

## formats/nxo

Construction, fusion et liaison des objets NXO.

| Fichier | Module déclaré | Points publics (extrait) |
|---|---|---|
| [nxo.nova](formats/nxo/nxo.nova) | `ntasm_nxo` | `Object`, `ReadResult`, `WriteResult`, `FORMAT_VERSION`, `CONTRACT_VERSION` |
| [nxo_link_pe.nova](formats/nxo/nxo_link_pe.nova) | `ntasm_nxo_link_pe` | `link_pe`, `link_pe_list` |
| [nxo_merge.nova](formats/nxo/nxo_merge.nova) | `ntasm_nxo_merge` | `merge`, `merge_list` |
| [nxo_pe.nova](formats/nxo/nxo_pe.nova) | `ntasm_nxo_pe` | `ConvertResult`, `convert` |

## formats/pe

Écriture du conteneur PE.

| Fichier | Module déclaré | Points publics (extrait) |
|---|---|---|
| [pe.nova](formats/pe/pe.nova) | `ntasm_pe` | `Image`, `Result`, `Value`, `align`, `put16` |

## inspectors

Lecture indépendante des formats pour inspection.

| Fichier | Module déclaré | Points publics (extrait) |
|---|---|---|
| [ntir_inspect.nova](inspectors/ntir_inspect.nova) | `ntasm_ntir_inspect` | `summary_words`, `inspect`, `inspect_node`, `typed_words`, `inspect_typed` |
| [nxo_inspect.nova](inspectors/nxo_inspect.nova) | `ntasm_nxo_inspect` | `inspect`, `inspect_symbol`, `inspect_relocation`, `copy_symbol_name`, `copy_symbol_contract` |
| [pe_inspect.nova](inspectors/pe_inspect.nova) | `ntasm_pe_inspect` | `summary_words`, `E_SHORT_OUTPUT`, `E_TRUNCATED_DOS`, `E_NOT_DOS`, `E_BAD_LFANEW` |

## drivers

Points d’entrée qui raccordent les modules à une commande ou au protocole natif.

| Fichier | Module déclaré | Points publics (extrait) |
|---|---|---|
| [machine-driver-entry.nova](drivers/machine-driver-entry.nova) | `machine_driver_entry` | `STAGE_LINK`, `STAGE_DELIVER`, `main` |
| [machine-link-entry.nova](drivers/machine-link-entry.nova) | `machine_link_entry` | `main` |
| [nova_native_driver.nova](drivers/nova_native_driver.nova) | `nova_native_driver` | `SOURCE_BYTES_LIMIT`, `SOURCE_COUNT_LIMIT`, `AST_NODES_LIMIT`, `MIR_WORDS_LIMIT`, `OUTPUT_BYTES_LIMIT` |
| [nova_native_driver_many.nova](drivers/nova_native_driver_many.nova) | `nova_native_driver_many` | `E_HEADER`, `E_MAGIC`, `E_ENVELOPE`, `E_COUNT`, `E_ROOT` |

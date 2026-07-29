use proc_macro::TokenStream;
use quote::{format_ident, quote, quote_spanned};
use syn::{parse_macro_input, spanned::Spanned, DeriveInput, Variant};

#[proc_macro_derive(Find)]
pub fn find_derive(input: TokenStream) -> TokenStream {
    let DeriveInput { ident, data, .. } = parse_macro_input!(input);

    let mut match_arms = vec![];
    match data {
        syn::Data::Enum(data_enum) => {
            for variant in data_enum.variants {
                let (_discr_u8, _variant_ident, fields) = match parse_variant(&variant) {
                    Ok(v) => v,
                    Err(e) => return e,
                };

                let mut fields_finds = vec![];
                let mut searchable_fields = vec![];
                for res in fields {
                    let (field_ty, field_ident) = match res {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    match field_ty {
                        FieldType::SearchableString => {
                            searchable_fields.push(field_ident.clone());
                            fields_finds.push(quote! {
                                if #field_ident.as_ref().starts_with(term) {
                                    return true;
                                };
                            });
                        }
                        _ => (),
                    }
                }
                let variant_ident = variant.ident;
                match_arms.push(quote! {
                    #ident::#variant_ident { #(#searchable_fields),*, .. } => {
                        #(#fields_finds);*
                        return false;
                    }

                })
            }

            quote! {
                impl Find for #ident {
                    fn find(&self, term: &str) -> bool {
                        match self {
                            #(#match_arms),*
                        }
                    }
                }

            }
            .into()
        }
        _ => {
            return quote_spanned! { ident.span() => compile_error!("only enums are supported"); }
                .into();
        }
    }
}

#[proc_macro_derive(Serialize)]
pub fn serialize_derive(input: TokenStream) -> TokenStream {
    let DeriveInput {
        ident, data, attrs, ..
    } = parse_macro_input!(input);

    if let Some(comp_err) = ensure_repr_u8(&ident, attrs) {
        return comp_err;
    }

    let mut enum_variant_outputs = vec![];
    match data {
        syn::Data::Enum(data_enum) => {
            for variant in data_enum.variants {
                let (discr_u8, variant_ident, fields) = match parse_variant(&variant) {
                    Ok(v) => v,
                    Err(e) => return e,
                };

                let mut fields_extends = quote! {};
                let mut fields_idents = vec![];
                for res in fields {
                    let (field_ty, field_ident) = match res {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    fields_idents.push(field_ident.clone());
                    match field_ty {
                        FieldType::U8 | FieldType::U32 | FieldType::U64 => {
                            fields_extends = quote! { #fields_extends result.extend(#field_ident.to_be_bytes()); }
                        }
                        FieldType::SearchableString | FieldType::NonSearchableString => {
                            fields_extends = quote! {
                                #fields_extends
                                result.extend(u32::try_from(#field_ident.0.len())
                                    .expect("len of fields should fit into u32").to_be_bytes());
                                result.extend(#field_ident.as_bytes());
                            }
                        }
                    }
                }

                let enum_variant_output = quote! {
                    #ident::#variant_ident { #(#fields_idents),* } => {
                        let mut result = vec![];
                        result.extend_from_slice(&#discr_u8.to_be_bytes());
                        #fields_extends
                        result
                    }
                };
                enum_variant_outputs.push(enum_variant_output);
            }
        }
        _ => {
            return quote_spanned! { ident.span() => compile_error!("only enums are supported"); }
                .into();
        }
    }

    let output = quote! {
        impl Serialize for #ident {
            fn serialize(self) -> Vec<u8> {
                match self {
                    #(#enum_variant_outputs),*
                }
            }
        }
    };
    output.into()
}

#[proc_macro_derive(Deserialize)]
pub fn deserilize_derive(input: TokenStream) -> TokenStream {
    let DeriveInput { ident, data, .. } = parse_macro_input!(input);

    let mut match_arms = vec![];
    match data {
        syn::Data::Enum(data_enum) => {
            for variant in data_enum.variants {
                let (discr_u8, variant_ident, fields) = match parse_variant(&variant) {
                    Ok(v) => v,
                    Err(e) => return e,
                };

                let mut fields_idents = vec![];
                let mut fields_reads = vec![];
                for res in fields {
                    let (field_ty, field_ident) = match res {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    fields_idents.push(field_ident.clone());
                    // let field_ty = &fields_tys[i];
                    match field_ty {
                        FieldType::U8 => {
                            fields_reads.push(
                                quote! { let (#field_ident, pos) = read_u8_as_usize(pos, &from)?; },
                            );
                        }
                        FieldType::U32 => {
                            fields_reads.push(
                                quote! { let (#field_ident, pos) = read_u32_as_usize(pos, &from)?; },
                            );
                        }
                        FieldType::U64 => {
                            fields_reads
                                .push(quote! { let (#field_ident, pos) = read_u64(pos, &from)?; });
                        }
                        FieldType::SearchableString | FieldType::NonSearchableString => {
                            let field_ident_len = format_ident!("{}_len", field_ident);
                            fields_reads.push(quote! {
                                let (#field_ident_len, pos) = read_u32_as_usize(pos, &from)?;
                                let (#field_ident, pos) = read_len(pos, #field_ident_len, &from)?;
                                let #field_ident = String::from_utf8(#field_ident.to_vec())?.into();
                            });
                        }
                    }
                }

                let match_arm = quote! {
                    #discr_u8 => {
                        #(#fields_reads)*

                        return Ok(#ident::#variant_ident {
                            #(#fields_idents),*
                        });
                    }
                };
                match_arms.push(match_arm);
            }
        }
        _ => {
            return quote_spanned! { ident.span() => compile_error!("only enums are supported"); }
                .into();
        }
    };

    quote! {
        impl Deserialize for #ident {
            fn deserialize(from: Vec<u8>) -> Result<Self, HushError> {
                use util::read_u8_as_usize;
                use util::read_u32_as_usize;
                use util::read_u64;
                use util::read_len;
                let (record_type, pos) = util::read_u8_as_usize(0, &from)?;
                match record_type {
                    #(#match_arms),*
                    n => Err(HushError::UnsupportedRecordType{type_id: n}),
                }
            }
        }

    }
    .into()
}

fn parse_variant(variant: &syn::Variant) -> Result<(u8, syn::Ident, EnumFields), TokenStream> {
    let discr_u8 = match variant_to_discr_u8(variant.clone()) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    Ok((
        discr_u8,
        variant.ident.clone(),
        EnumFields::new(variant.clone()),
    ))
}

struct EnumFields {
    fields_iter: syn::punctuated::IntoIter<syn::Field>,
}

impl EnumFields {
    fn new(variant: Variant) -> Self {
        Self {
            fields_iter: variant.fields.into_iter(),
        }
    }
}

impl Iterator for EnumFields {
    type Item = Result<(FieldType, syn::Ident), TokenStream>;

    fn next(&mut self) -> Option<Self::Item> {
        let field = self.fields_iter.next()?;
        Some(Self::process_field(&field))
    }
}

impl EnumFields {
    fn process_field(field: &syn::Field) -> Result<(FieldType, syn::Ident), TokenStream> {
        let Some(field_idnt) = field.ident.clone() else {
            return Err(quote_spanned! { field.ty.span() =>
                compile_error!("tuples are not supported");
            }
            .into());
        };
        let field_ty = get_field_type(field)?;
        Ok((field_ty, field_idnt))
    }
}

fn ensure_repr_u8(ident: &syn::Ident, attrs: Vec<syn::Attribute>) -> Option<TokenStream> {
    // check that repr u8 is there
    match attrs.iter().find(|a| {
        let is_repr = a.path().is_ident("repr");
        let has_u8 = a.parse_nested_meta(|meta| {
            meta.path
                .is_ident("u8")
                .then_some(())
                .ok_or(meta.error("not u8"))
        });
        is_repr && has_u8.is_ok()
    }) {
        Some(_) => None,
        None => {
            Some(quote_spanned! { ident.span() => compile_error!("only enums with #repr[u8] are supported"); }.into())
        }
    }
}

fn get_field_type(field: &syn::Field) -> Result<FieldType, TokenStream> {
    let sp = field.ty.span();
    match &field.ty {
        syn::Type::Path(type_path) => {
            if type_path.path.is_ident("u8") {
                return Ok(FieldType::U8);
            }
            if type_path.path.is_ident("u32") {
                return Ok(FieldType::U32);
            }
            if type_path.path.is_ident("u64") {
                return Ok(FieldType::U64);
            }
            if type_path.path.is_ident("SearchableString") {
                return Ok(FieldType::SearchableString);
            }
            if type_path.path.is_ident("NonSearchableString") {
                return Ok(FieldType::NonSearchableString);
            }
            return Err(
                quote_spanned! { sp => compile_error!("only u8, u32, u64, Searchable-, NonSearchableString field types are supported"); }.into(),
            );
        }
        _ => {
            return Err(
                    quote_spanned! { sp => compile_error!("only u8, u32, u64, Searchable-, NonSearchableString field types are supported"); }.into(),
                )
        }
    }
}

#[derive(Debug)]
enum FieldType {
    U8,
    U32,
    U64,
    SearchableString,
    NonSearchableString,
    // VecU8,
}

fn variant_to_discr_u8(variant: Variant) -> Result<u8, TokenStream> {
    let sp = variant.span();
    let variant_discr = variant
        .discriminant
        .expect("variants without discriminants are not allowed");
    match variant_discr.1 {
        syn::Expr::Lit(expr_lit) => match expr_lit.lit {
            syn::Lit::Int(lit_int) => Ok(lit_int
                .base10_parse::<u8>()
                .map_err(|_| quote_spanned! { sp => compile_error!("can't parse discriminant as u8"); })?
            ),
            _ => Err(quote_spanned! { sp => compile_error!("only literal discriminants are supported"); }.into()),
        },
        _ => Err( quote_spanned! { sp => compile_error!("only literal discriminants are supported"); }.into(),
        ),
    }
}

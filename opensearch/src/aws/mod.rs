/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

/// Re-exports of the relevant crates from the AWS SDK for Rust
pub mod sdk {
    pub use aws_config as config;
    pub use aws_credential_types as credentials;
    pub use aws_types as types;
    pub use aws_smithy_async::time as time;
}

mod sigv4;

pub use sigv4::*;

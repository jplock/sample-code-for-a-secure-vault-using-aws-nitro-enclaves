// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use clap::Parser;
use parent_vault::configuration::ParentOptions;
use parent_vault::enclaves::Enclaves;
use parent_vault::{application::Application, constants};
use std::{io::Error, sync::Arc};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Error> {
    // (Initial "init" message removed; tracing::info!("[parent] {:?}", &options)
    // below runs after the subscriber is up and gets shipped to CloudWatch.)

    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,tower_http=debug".into()),
        ))
        // this needs to be set to remove duplicated information in the log.
        .with_current_span(false)
        // this needs to be set to false, otherwise ANSI color codes will
        // show up in a confusing manner in CloudWatch logs.
        .with_ansi(false)
        // disabling time is handy because CloudWatch will add the ingestion time.
        .without_time()
        // remove the name of the function from every log entry
        .with_target(false)
        .init();

    // get configuration options from environment variables
    let options = ParentOptions::parse();

    tracing::info!("[parent] {:?}", &options);

    let enclaves = Arc::new(Enclaves::new());

    if !options.skip_refresh_enclaves {
        tracing::info!(
            "[parent] refreshing enclaves every {:#?}",
            constants::REFRESH_ENCLAVES_INTERVAL
        );

        // Perform one synchronous refresh before serving traffic so the HTTP
        // server does not accept `/decrypt` requests during the cold-start
        // window where the enclave list is still empty. Bounded by a timeout so
        // a hung `nitro-cli` cannot block startup forever — on failure/timeout
        // we log and start anyway, letting the background loop recover.
        match tokio::time::timeout(
            constants::INITIAL_REFRESH_TIMEOUT,
            enclaves.refresh(options.skip_run_enclaves),
        )
        .await
        {
            Ok(Ok(())) => tracing::info!("[parent] initial enclave refresh complete"),
            Ok(Err(e)) => {
                tracing::error!("[parent] initial enclave refresh failed: {:?}", e)
            }
            Err(_) => tracing::error!(
                "[parent] initial enclave refresh timed out after {:#?}",
                constants::INITIAL_REFRESH_TIMEOUT
            ),
        }

        let enclaves_mut = enclaves.clone();
        tokio::spawn(async move {
            loop {
                // Sleep first: the initial refresh above already ran, so waiting
                // one interval before the next refresh avoids racing it (which
                // could otherwise double-launch enclaves).
                tokio::time::sleep(constants::REFRESH_ENCLAVES_INTERVAL).await;
                if let Err(e) = enclaves_mut.refresh(options.skip_run_enclaves).await {
                    tracing::error!("[parent] failed to refresh enclaves: {:?}", e);
                }
                tracing::debug!(
                    "[parent] refreshed enclaves, sleeping for {:#?}",
                    constants::REFRESH_ENCLAVES_INTERVAL
                );
            }
        });
    } else {
        tracing::warn!("[parent] skipping refreshing enclaves");
    }

    let application = Application::build(options, enclaves).await?;

    application.run_until_stopped().await
}

/*
.subcommand(
    Command::new("provision-piv")
        .about("Provision this slot with a new private key")
        .arg(
            Arg::new("management-key")
                .help("Specify the management key")
                .default_value("010203040506070801020304050607080102030405060708")
                .long("mgmkey")
                .short('m')
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::new("pin-env")
                .help("Specify the pin")
                .default_value("YK_PIN")
                .long("pinenv")
                .short('p')
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::new("require-touch")
                .help("Require the key to always be tapped. If this is not selected, a tap will be required if not tapped in the last 15 seconds.")
                .long("require-touch")
                .short('r')
        )
                .arg(
            Arg::new("pin-env")
                .help("Specify the pin environment variable")
                .default_value("YK_PIN")
                .long("pinenv")
                .short('p')
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::new("subject")
                .help("Subject of the new cert you're creating (this is only used as a note)")
                .default_value("Rustica-AgentQuickProvision")
                .long("subj")
                .short('j')
        )
) */

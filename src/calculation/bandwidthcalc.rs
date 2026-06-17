// * 8 to go from bytes to bits
pub(crate) fn run() {
    calculate_wonderboom(false);
    calculate_ethereum(false);
}

fn calculate_ethereum(verbose: bool) {
    let mb = 1000.0*1000.0;

    let ethereum_m = [512.0, 650.0, 820.0, 1018.0, 1250.0];
    let gossip_send = | m:f64 | ((m * 64.0 + 104.0*8.0)) * 8.0 ; // 16 Aggregators send m * 64.0 + 104.0 to Gossip

    let send_steps = [
        | m:f64 | 104.0*8.0 * m, // 104 bytes from leaf to m parents.
        gossip_send //
    ];

    let gossip_receive = | m:f64 | (16.0 * (m * 64.0 + 104.0*8.0) * 32.0); // Leader receives 296+m*(m/16)*(m/16)*(m/16)*2 * 16 from gossip

    let receive_steps = [
        | m:f64 | 104.0*8.0 * m, // Each leaf aggregator receives 104 bytes from m children.
        gossip_receive
    ];

    for m in ethereum_m {
        if verbose {
            println!("{} Ethereum", m);

            println!("Send");
            for (i, step) in send_steps.iter().enumerate() {
                println!("{} {}", i, step(m) / mb);
            }

            println!("Receive");
            for (i, step) in receive_steps.iter().enumerate() {
                println!("{} {}", i, step(m) / mb);
            }

            //println!("Gossip Send {}, Gossip Recv {}", gossip_send(m)/mb, gossip_receive(m)/mb);
            println!("---------------------");
        } else {
            let mut sum = 0.0;
            for (i, step) in send_steps.iter().enumerate() {
                sum = sum + step(m);
            }

            for (i, step) in receive_steps.iter().enumerate() {
                sum = sum + step(m);
            }

            println!("{} Ethereum: {}", m, sum/mb/100.0);
        }
    }
}

fn calculate_wonderboom(verbose: bool) {
    let mb = 1000.0*1000.0;

    let wonderboom_m = [256.0, 272.0, 288.0, 304.0, 320.0];
    let gossip_send = | m:f64 | (296.0*8.0 + m * (m/16.0) * (m/16.0) * (m/16.0) * 2.0) * 8.0; // 16 Aggregators send 296+m*(m/16)*(m/16)*(m/16)*2 to Gossip

    let send_steps = [
        | m:f64 | 104.0*8.0 * 128.0, // 104 bytes from leaf to 128 parents. 0.013312 = 10k = 0.001ms
        | m | (200.0*8.0 + m) * 128.0, // 200 + m bits from leaf aggregator to 128 aggregators. 0.058368 = 50k = 0.005ms
        | m | (296.0*8.0 + m * (m/16.0) * 2.0) * 128.0, // Each internal aggregator sends 296+m*(m/16)*2 to 128. 1.086464 = 10ms
        | m | (296.0*8.0 + m * (m/16.0) * (m/16.0) * 2.0) * 128.0, // Aggregator sends 296+m*(m/16)*(m/16)*2 to 128. 16.815104 = 160ms // 32 = 320ms
        gossip_send // 2.097448 * 8 = 16 = 160ms // 40 = 400ms
    ];

    // Increases linearly with validator set (dominated by bitset)

    let gossip_receive = | m:f64 | (296.0*8.0 + m * (m/16.0) * (m/16.0) * (m/16.0) * 2.0) * 16.0; // Leader receives 296+m*(m/16)*(m/16)*(m/16)*2 * 16 from gossip

    let receive_steps = [
        | m:f64 | 104.0*8.0 * m, // Each leaf aggregator receives 104 bytes from m children. 0.026624 = 20k = 0.002ms
        | m | (200.0*8.0 + m) * m, // First internal aggregator receives 200+m bytes from m children (16 duplicates). 0.116736 = 116k = 0.01ms
        | m | (296.0*8.0 + m * (m/16.0) * 2.0) * m, // Each aggregator receives 296+m*(m/16)*(m/16)*2 from m children. 2.172928 = 20ms
        | m | (296.0*8.0+ m * (m/16.0) * (m/16.0) * 2.0) * m, // Each aggregator receives 296+m*(m/16)*(m/16)*(m/16)*2 from m children. 33.630208 = 320ms
        gossip_receive // 33.630208 = 320ms
    ];

    for m in wonderboom_m {
        if verbose {
            println!("{} Wonderboom", m);

            println!("Send");
            for (i, step) in send_steps.iter().enumerate() {
                println!("{} {}", i, step(m) / mb);
            }

            println!("Receive");
            for (i, step) in receive_steps.iter().enumerate() {
                println!("{} {}", i, step(m) / mb);
            }

            //println!("Gossip Send {}, Gossip Recv {}", gossip_send(m)/mb, gossip_receive(m)/mb);
            println!("---------------------")
        } else {
            let mut sum = 0.0;
            for (i, step) in send_steps.iter().enumerate() {
                sum = sum + step(m);
            }

            for (i, step) in receive_steps.iter().enumerate() {
                sum = sum + step(m);
            }

            println!("{} Wonderboom: {}", m, sum/mb/100.0);
        }
    }
}
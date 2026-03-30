// Unlicense — cochranblock.org
// Contributors: GotEmCoach, KOVA, Claude Opus 4.6
//! aptnomo test binary. Exopack TRIPLE SIMS gate.
//! Runs compilation check 3 times. All must pass.

fn main() {
    #[cfg(feature = "tests")]
    {
        let project_dir = std::env::current_dir().expect("failed to get cwd");

        eprintln!("aptnomo-test: TRIPLE SIMS gate");
        eprintln!("project: {}", project_dir.display());

        let mut all_pass = true;
        for i in 1..=3 {
            eprintln!("── run {}/3 ──", i);
            let (pass, output) = exopack::triple_sims::f61(&project_dir, i);
            if !pass {
                eprintln!("FAIL on run {}: {}", i, output);
                all_pass = false;
                break;
            }
            eprintln!("PASS run {}/3", i);
        }

        if all_pass {
            eprintln!("TRIPLE SIMS: ALL PASS");
        } else {
            eprintln!("TRIPLE SIMS: FAILED");
        }
        std::process::exit(if all_pass { 0 } else { 1 });
    }

    #[cfg(not(feature = "tests"))]
    {
        eprintln!("aptnomo-test: requires --features tests");
        std::process::exit(1);
    }
}

from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

# The data files have no header row, so I write the column names myself.
columns = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty",
]

# Three columns are text, so I turn them into numbers.
text_columns = ["protocol_type", "service", "flag"]

# Where the data files live, relative to this script.
DATA = Path(__file__).resolve().parent.parent / "data"

# Each raw attack name belongs to one of four attack groups.
attack_groups = {
    "DoS": ["back", "land", "neptune", "pod", "smurf", "teardrop", "mailbomb",
            "apache2", "processtable", "udpstorm", "worm"],
    "Probe": ["satan", "ipsweep", "nmap", "portsweep", "mscan", "saint"],
    "R2L": ["guess_passwd", "ftp_write", "imap", "phf", "multihop",
            "warezmaster", "warezclient", "spy", "xlock", "xsnoop", "snmpguess",
            "snmpgetattack", "httptunnel", "sendmail", "named"],
    "U2R": ["buffer_overflow", "loadmodule", "rootkit", "perl", "sqlattack",
            "xterm", "ps"],
}


def load(name):
    # Read one data file and give the columns their names.
    df = pd.read_csv(DATA / name, names=columns)
    # Drop the difficulty column, I do not use it.
    return df.drop(columns=["difficulty"])


def main():
    train = load("KDDTrain+.txt")
    test = load("KDDTest+.txt")

    # Make a simple label: 0 for normal, 1 for any attack.
    train_y = (train["label"] != "normal").astype(int)
    test_y = (test["label"] != "normal").astype(int)

    # Keep the raw attack names from the test set to break results down later.
    test_names = test["label"].values

    # Turn the three text columns into number columns using one hot encoding.
    train_x = pd.get_dummies(train.drop(columns=["label"]), columns=text_columns)
    test_x = pd.get_dummies(test.drop(columns=["label"]), columns=text_columns)

    # Line up the test columns to match the training columns.
    test_x = test_x.reindex(columns=train_x.columns, fill_value=0)

    # Train a random forest, which is a group of decision trees that vote.
    print("Training the model, this takes a moment.")
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(train_x, train_y)

    # Score it on the test set.
    pred = model.predict(test_x)
    print("\nAccuracy on the held out test set:", round(accuracy_score(test_y, pred), 3))
    print()
    print(classification_report(test_y, pred, target_names=["normal", "attack"]))

    # Break the attacks down by type to see which ones the model catches.
    results = pd.DataFrame({"name": test_names, "caught": pred})
    print("Detection rate by attack type:")
    for group, names in attack_groups.items():
        rows = results[results["name"].isin(names)]
        if len(rows) == 0:
            continue
        # caught is 1 when the model flagged it as an attack, so the mean is the rate.
        print(f"  {group}: {rows['caught'].mean():.0%} caught")


if __name__ == "__main__":
    main()

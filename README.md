# Network Intrusion Detection

This is my network intrusion detection project. I wanted to see if I could train a model to tell normal network traffic apart from attacks, using real data that security people actually study.

It uses the NSL KDD dataset, which is a well known benchmark for this kind of task. Each row is one network connection described by 41 features, and the job is to flag the bad ones.

This is a learning project, not a real security tool. I kept it honest and simple on purpose.

## What it does

1. Reads the connection records and names the 41 columns.
2. Turns the three text columns (protocol, service, flag) into number columns.
3. Lines up the test columns to match the training columns.
4. Trains a random forest, which is a group of decision trees that vote.
5. Scores it on the official test set and breaks the results down by attack type.

## Results

Accuracy on the held out test set was about 77 percent. The model is very precise when it does flag an attack, about 97 percent, but it misses a fair share of them, catching about 61 percent. The most interesting part was the breakdown by attack type:

1. DoS: caught about 79 percent
2. Probe: caught about 73 percent
3. R2L: caught about 5 percent
4. U2R: caught about 12 percent

So the model is good at the loud, high volume attacks like DoS and Probe, but almost blind to the rare, quiet ones like R2L and U2R. That is not a bug. The test set on purpose includes attack types that barely show up in the training data, so the model has almost no examples to learn them from. This is a known thing about NSL KDD, and seeing it in my own results taught me why accuracy on its own can hide a real problem.

## How to run it

The dataset is already included, so you do not need to download anything.

```
pip install -r requirements.txt
cd src
python intrusion_detection.py
```

## What's next

Things I want to improve as I keep learning:

1. Predict the exact attack type, not just normal versus attack.
2. Fix the weak spot on rare attacks by balancing the classes or finding more examples of them.
3. Try other models like logistic regression or gradient boosting and compare.
4. Add a simple chart so the results are easier to read at a glance.
5. Look at which features mattered most and explain why.

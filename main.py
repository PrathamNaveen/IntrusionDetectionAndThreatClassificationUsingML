# Main Python Code for the ML Model used for Intrusion Detection and Threat Classification

import numpy as np
import pandas as pd
import os
import seaborn as sns
import matplotlib.pyplot as plt

path = "MachineLearningCVE/"
csv_files = []
for root, directories, files in os.walk(path):
    for file in files:
        csv_files.append(os.path.join(root, file))

[print(f) for f in csv_files]

dataset = [pd.read_csv(f) for f in csv_files]

# Shape of each csv file
for d in dataset:
    print(d.shape)

dataset[0].columns

# Check whether all the columns in every csv file is the same

for i in range(len(dataset)):
    if i != len(dataset) - 1:
        same_columns = dataset[i].columns == dataset[i+1].columns
        
        if False in same_columns:
            print(i)
            break

same_columns

# Assuming dataset is a list containing DataFrames or Series objects
valid_data = [d for d in dataset if isinstance(d, (pd.DataFrame, pd.Series))]

# Concatenate the valid DataFrames or Series objects
if valid_data:
    dataset = pd.concat(valid_data).drop_duplicates(keep=False)
    dataset.reset_index(drop=True, inplace=True)
    print("Combined dataset created successfully.")
else:
    print("No valid data found in the dataset list.")

# We can observe that all the datasets are merged into one
dataset.shape

dataset.info()

dataset.describe()

dataset.columns

dataset[' Label'].unique()

len(dataset[' Label'].unique())

dataset.head()

data = dataset[' Label'].where(dataset[' Label'] != "BENIGN")

plt.figure(figsize=(14,6))
# Plotting non-benign data since there are a lot of benign samples
chart = sns.countplot(data, palette="Set1")
plt.xticks(horizontalalignment="right")

# Removing whitespaces in column names.

col_names = [col.replace(' ', '') for col in dataset.columns]
dataset.columns = col_names
dataset.columns

# Here we can see that 'Label' column contains some weird characters. 

dataset["Label"].unique()

# Removing the weird characters

label_names = dataset['Label'].unique()


import re

label_names = [re.sub("[^a-zA-Z ]+", "", l) for l in label_names]
label_names = [re.sub("[\s\s]", '_', l) for l in label_names]
label_names = [l.replace("__", "_") for l in label_names]

label_names, len(label_names)

prev_labels = dataset['Label'].unique()
prev_labels

# Replacing Previous labels with the cleaned labels
for i in range(len(label_names)):
    dataset['Label'] = dataset['Label'].replace({prev_labels[i] : label_names[i]})
    
dataset['Label'].unique()

dataset.isnull().values.any()

# Check which column has null value and 

[col for col in dataset if dataset[col].isnull().values.any()]

# Check how many rows have it
dataset['FlowBytes/s'].isnull().sum()

# Since only a small number of rows contain NULL value, We will remove them
dataset.dropna(inplace=True)

# Observe that null valued rows are successfully removed
dataset.isnull().values.any()

# Removing label column for now because it has string values

label = dataset['Label']
dataset = dataset.loc[:, dataset.columns != 'Label'].astype('float64')

# Checking if all values are finite.

np.all(np.isfinite(dataset))

# Checking what column/s contain non-finite values.

nonfinite = [col for col in dataset if not np.all(np.isfinite(dataset[col]))]

nonfinite

# Checking how many non-finite values each column contains.

finite = np.isfinite(dataset['FlowPackets/s']).sum()

# Infinite = Total - Finite 
dataset.shape[0] - finite

# Since there is a small number of non-finite values we can safely remove them from the dataset without spoiling the dataset

# Replacing infinite values with NaN values.
dataset = dataset.replace([np.inf, -np.inf], np.nan)

# We can see that now we have Nan values again.

np.any(np.isnan(dataset))

# Adding the Labels column back again

dataset = dataset.merge(label, how='outer', left_index=True, right_index=True)

# Removing new NaN values.

dataset.dropna(inplace=True)

dataset.head()

from sklearn.preprocessing import RobustScaler

# Splitting dataset into features and labels.

labels = dataset['Label']
features = dataset.loc[:, dataset.columns != 'Label'].astype('float64')

features.head()

scaler = RobustScaler()
scaler.fit(features)

features = scaler.transform(features)

# Checking if scaling has been succesful.
features[0]

from sklearn.preprocessing import LabelEncoder

LE = LabelEncoder()

LE.fit(labels)
labels = LE.transform(labels)

# labels have been replaced with integers.

np.unique(labels)

# Checking that encoding reversal works.

# d = LE.inverse_transform(labels)
# d = pd.Series(d)
# d.unique()

from sklearn.model_selection import train_test_split

# For this we will use sklearn function train_test_split().

# 80-20 split
features_train, features_test, labels_train, labels_test = train_test_split(features, labels, test_size = 0.2)

features_train.shape, features_test.shape, labels_train.shape, labels_test.shape

import tensorflow as tf

model = tf.keras.models.Sequential([
    
    tf.keras.layers.Flatten(input_shape=(78,)),
    tf.keras.layers.Dense(67, activation='relu'),
    tf.keras.layers.Dropout(0.2),
    tf.keras.layers.Dense(15, activation='softmax')
])

# For learning rate optimization we used Adam optimizer.
# Loss function used is sparse categorical crossentropy, which is standard for multiclass classification problems.

model.compile(optimizer='adam',
             loss='sparse_categorical_crossentropy',
             metrics=['accuracy'])

# log_dir = os.path.join(
#     "train_logs",
#     datetime.datetime.now().strftime("%Y%m%d-%H%M%S"),
# )

# # TF callback that sets up TensorBoard with training logs.
# tensorboard_callback = tf.keras.callbacks.TensorBoard(log_dir=log_dir, histogram_freq=1)

# # TF callback that stops training when best value of validationi loss function is reached. It also
# # restores weights from the best training iteration.
# eary_stop_callback = tf.keras.callbacks.EarlyStopping(monitor='loss', patience=10, restore_best_weights=True)

features_train.shape

print(features_test[:5])

model.fit(features_train,
          labels_train,
          epochs=5,
         )

# Evaluating model accuracy.
model.evaluate(features_test, labels_test, verbose=2)

predictions = model.predict(features_test)

predicted_indices = predictions.argmax(axis=1)
predicted_labels = [label_names[i] for i in predicted_indices]
predicted_labels

# Define a dictionary mapping attack labels to their severity levels
severity_mapping = {
    'BENIGN': 'Low',
    'DDoS': 'High',
    'PortScan': 'Medium',
    'Bot': 'High',
    'Infiltration': 'High',
    'Web_Attack_Brute_Force': 'Medium',
    'Web_Attack_XSS': 'Medium',
    'Web_Attack_Sql_Injection': 'High',
    'FTPPatator': 'Medium',
    'SSHPatator': 'Medium',
    'DoS_slowloris': 'High',
    'DoS_Slowhttptest': 'High',
    'DoS_Hulk': 'High',
    'DoS_GoldenEye': 'High',
    'Heartbleed': 'High'
}

# Get the predicted labels for the attacks
predicted_labels = [label_names[np.argmax(pred)] for i, pred in enumerate(predictions[:1000]) if label_names[np.argmax(pred)] != 'BENIGN']

# Create a list to store the severity levels for each predicted label
severity_levels = [severity_mapping[label] for label in predicted_labels]

# Combine predicted labels and severity levels
predicted_attacks_with_severity = zip(predicted_labels, severity_levels)

# Display the predicted attacks with their severity levels
for attack, severity in predicted_attacks_with_severity:
    print(f"Predicted Attack: {attack}, Severity: {severity}")

dataset.to_csv("cleaned_dataset.csv", index=False)

model.save('trained_model.keras')

dataset = pd.read_csv('cleaned_dataset.csv')

model = tf.keras.models.load_model('trained_model.keras')

from secret import RealTimeData

real_time_data_instance = RealTimeData()

real_time_data = real_time_data_instance.get_cleaned_real_time_data()

real_time_data
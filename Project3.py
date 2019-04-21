import pandas as pd
import numpy as np
import keras
from keras.models import Sequential
from keras.layers import Dense
from sklearn.utils import shuffle
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import OneHotEncoder, LabelEncoder
from sklearn.compose import ColumnTransformer,make_column_transformer
from sklearn.metrics import accuracy_score
import os
import matplotlib.pyplot as plt
from keras.utils import plot_model
from sklearn.metrics import confusion_matrix
import time

os.environ['KMP_DUPLICATE_LIB_OK']='True'
# Some globals
data_set_path = 'NSL-KDD/KDDTrain+.txt'
test_data_set_path = 'NSL-KDD/KDDTest+.txt'
headers = ['duration', 'protocol_type','service','flag', 'src_bytes', 'dst_bytes','land', 'wrong_fragment', 'urgent', 'hot',
         'num_failed_logins', 'logged_in','num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
         'num_shells', 'num_access_files', 'num_outbound_cmds',  'is_host_login', 'is_guest_login', 'count', 'srv_count',
         'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate','srv_diff_host_rate',
         'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
         'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate','dst_host_srv_rerror_rate',
         'type', 'difficulty']

# Reads the test datafile, removes the training attacks and replaces all attack names with 'attack', and returns.
def prepare_test_data(attack1, attack2):
    test_dataset = pd.read_csv(test_data_set_path, names=headers, header=0)
    test_dt = test_dataset.loc[(test_dataset['type'] != attack1) & (test_dataset['type'] != attack2)]
    test_dt['type'] = test_dt['type'].str.replace(r"^(.(?<!normal))*?$", "attack")
    return test_dt

# This function returns a "train_data" df based on the two attacks selected
def prepare_train_subset(normal_data, full_dataset, attack1, attack2):
    train_subset = normal_data.copy()
    attack1_data = full_dataset.loc[full_dataset['type'] == attack1]
    attack2_data = full_dataset.loc[full_dataset['type'] == attack2]
    train_subset = train_subset.append(attack1_data)
    train_subset = train_subset.append(attack2_data)
    train_subset = train_subset.replace(attack1, 'attack')
    train_subset = train_subset.replace(attack2, 'attack')
    print("Training subset with " + attack1 + " and " + attack2 + " with shape ")
    print(train_subset.shape)
    return shuffle(train_subset)

# Used in encoding uniformly. This returns unique categories across the train  & test datasets
def get_unique_categories(train_data, test_data):
    temp_service = train_data.service.unique().tolist()
    temp_service.extend(test_data.service.unique().tolist())
    service_categories = set(temp_service)
    services = [ x for x in iter(service_categories) ]

    protocol_type = train_data.protocol_type.unique().tolist()
    protocol_type.extend(test_data.protocol_type.unique().tolist())
    protocol = set(protocol_type)
    protocols = [x for x in iter(protocol)]


    flag = train_data.flag.unique().tolist()
    flag.extend(test_data.flag.unique().tolist())
    flag_val = set(flag)
    flag_values = [x for x in iter(flag_val)]


    categories = [protocols, services, flag_values]
    return categories

# Do label and one hot encoding on the train and test datasets
def encode_values(X, test_X, Y, test_Y, categories):
    # First label encode 'normal' and 'attack' labels
    labelencoder_Y = LabelEncoder()
    processed_Y = labelencoder_Y.fit_transform(Y)
    processed_test_Y = labelencoder_Y.transform(test_Y)

    preprocess = OneHotEncoder(categories=categories)
    processed_X = preprocess.fit_transform(X[:,1:4]).toarray()
    processed_X = pd.concat([pd.DataFrame(X[:,0]), pd.DataFrame(processed_X), pd.DataFrame(X[:,5:])], axis=1, ignore_index=True).values
    processed_test_X = preprocess.transform(test_X[:, 1:4]).toarray()
    processed_test_X = pd.concat([pd.DataFrame(test_X[:,0]), pd.DataFrame(processed_test_X), pd.DataFrame(test_X[:,5:])], axis=1, ignore_index=True).values

    print("Shape of train data after encoding is {0} and test data is {1}".format(processed_X.shape, processed_test_X.shape))
    return processed_X, processed_test_X, processed_Y, processed_test_Y

# Train the FNN. Split train data to train & validation, encode train, validation and test datasets, predict results and return the history obj for visualization
def train_nn(train_data, test_data):
    categories = get_unique_categories(train_data, test_data)
    X = train_data.iloc[:, 0:-2].values
    Y = train_data.iloc[:, -2].values
    test_X = test_data.iloc[:, 0:-2].values
    test_Y = test_data.iloc[:, -2].values
    print("Training data has shape of {0} and test data has shape of {1}".format(X.shape, test_X.shape))
    X_Train, X_Test, Y_Train, Y_Test = encode_values(X, test_X, Y, test_Y, categories)
    sc = StandardScaler()
    X_Train = sc.fit_transform(X_Train)
    X_Test = sc.transform(X_Test)
    print("Shapes of train and test data are {0}, {1}".format(X_Train.shape, X_Test.shape))
    x_train,x_valid,y_train,y_valid = train_test_split(X_Train, Y_Train, test_size = 0.15, random_state = 42)
    classifier = Sequential()
    classifier.add(Dense(units = 12, kernel_initializer = 'uniform', activation = 'relu', input_dim = x_train.shape[1]))
    classifier.add(Dense(units = 12, kernel_initializer = 'uniform', activation = 'relu'))
    classifier.add(Dense(units = 1, kernel_initializer = 'uniform', activation = 'sigmoid'))
    classifier.compile(optimizer = 'adam', loss = 'binary_crossentropy', metrics = ['acc'])
    classifierHistory = classifier.fit(x_train, y_train, batch_size = 100, validation_data=(x_valid, y_valid), epochs = 100)
    y_pred = classifier.predict(X_Test)
    y_pred = (y_pred > 0.9)
    return accuracy_score(Y_Test, y_pred), classifierHistory, Y_Test, y_pred

# Plots a graph given all params.
def plot_graph(values, title, xlabel, ylabel, legend):
    # Plot training & validation accuracy values
    plt.clf()
    for value in values:
        plt.plot(value)
    plt.title(title)
    plt.ylabel(ylabel)
    plt.xlabel(xlabel)
    plt.legend(legend, loc='upper left')
    plt.show()

# Helper to plot a bar graph.
def show_bar(xLabels, values, title, yLabel):
    plt.clf()
    y_pos = np.arange(len(xLabels))
    plt.barh(y_pos, values)
    plt.title(title)
    plt.yticks(y_pos, xLabels)
    plt.xlabel(yLabel)
    plt.show()

# Visualization driver. Plots graphs and bar charts
def visualize(results):
    legends = results['attacks']
    plot_graph(results['acc'], "Model Accuracy", "Epochs", "Accuracy", legends)
    plot_graph(results['val_acc'], "Model Validation Accuracy", "Epochs", "Valdiation Accuracy", legends)
    plot_graph(results['loss'], "Model Loss", "Epochs", "Loss", legends)
    plot_graph(results['val_loss'], "Model Validation Loss", "Epochs", "Validation Loss", legends)
    show_bar(legends, results['accuracy'], "Test Accuracy of each combination", "Test Accuracy")
    show_bar(legends, results['time'], "Time Taken to train each comibation", "Time (in seconds)")

#driver method
def main():
    attack2_types = ['neptune', 'warezmaster', 'nmap', 'teardrop']
    attack1_types = ['satan', 'portsweep', 'buffer_overflow','multihop']
    full_dataset = pd.read_csv(data_set_path, names=headers, header=0)
    val = pd.value_counts(full_dataset['type'])
    Labels = val.index.values
    Values = val.tolist()
    show_bar(Labels, Values,'Distribution of Attacks', 'Number of Samples')
    # First grab the normal data out
    normal_data = full_dataset.loc[full_dataset['type'] == 'normal']
    results = { "attacks" : [], "loss" : [], "val_loss" :[], "accuracy": [], "acc": [], "val_acc":[], "time": [], "cm": []}
    for attack1, attack2 in zip(attack1_types, attack2_types):
        test_dataset = prepare_test_data(attack1, attack2)
        train_df = prepare_train_subset(normal_data, full_dataset, attack1, attack2)
        start_time = time.time()
        accuracy, classifierHistory, y_test, y_pred = train_nn(train_df, test_dataset)
        time_taken = time.time() - start_time
        results["attacks"].append("{0} and {1}".format(attack1, attack2))
        results["accuracy"].append(accuracy)
        results["loss"].append(classifierHistory.history['loss'])
        results["val_loss"].append(classifierHistory.history['val_loss'])
        results["acc"].append(classifierHistory.history['acc'])
        results["val_acc"].append(classifierHistory.history['val_acc'])
        results["time"].append(time_taken)
        print("Dataset has {0} and {1} attacks. The accuracy score was {2}".format(attack1, attack2, accuracy))
        tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
        results["cm"].append([tn, fp, fn, tp])
        del(train_df)
        del(test_dataset)
    visualize(results)
    print(results["attacks"])
    print(results["cm"])
if __name__== "__main__":
    main()

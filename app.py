import streamlit as st
import pandas as pd
import numpy as np
from sklearn import preprocessing
import time
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, accuracy_score
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score, roc_curve, auc, precision_recall_curve, classification_report
from sklearn.decomposition import PCA

# Function to process PCAP file
def process_pcap(file):

    # Read PCAP file into Raw_Data (assuming it's CSV for now)
    Raw_Data = pd.read_csv(file, index_col="No.")
    st.write("## before Processed data:")
    st.write(Raw_Data.head())
    # Conversion to numpy array
    np_Raw_Data = np.array(Raw_Data)

    # Sorting data on axis 0 (axis 0 is time values.)
    np_Raw_Data = np_Raw_Data[np.argsort(np_Raw_Data[:, 0])]

    # Calculate packet durations
    packetDurations = []
    counter = 0
    while counter < len(np_Raw_Data):
        duration = 0
        if counter != 0 and counter + 1 < len(np_Raw_Data):
            duration = np.float32(np_Raw_Data[counter][0]) - np.float32(np_Raw_Data[counter - 1][0])
        packetDurations.append(duration)
        counter += 1

    packetDurations = np.delete(packetDurations, 0, axis=0)
    np_Raw_Data = np.delete(np_Raw_Data, len(np_Raw_Data) - 1, axis=0)
    np_Raw_Data = np.insert(np_Raw_Data, 1, packetDurations, axis=1)

    # Unique values of source and destination IPs, info, and protocols
    source_unique_array = np.unique(np.array(Raw_Data.iloc[:, 1:2].astype(str)))
    destination_unique_array = np.unique(np.array(Raw_Data.iloc[:, 2:3].astype(str)))
    info_unique_array = np.unique(np.array(Raw_Data.iloc[:, 5:6]))
    protocol_unique_array = np.unique(np.array(Raw_Data.iloc[:, 3:4]))

    all_ip_addresses = np.concatenate((source_unique_array, destination_unique_array))
    all_ip_addresses = np.unique(all_ip_addresses)

    # Label encoding for IP addresses
    le = preprocessing.LabelEncoder()
    lb_all_ip_addresses = le.fit_transform(all_ip_addresses)
    ip_dict = {ip: num for ip, num in zip(all_ip_addresses, lb_all_ip_addresses)}

    # Sorting data again on axis 0 (time values.)
    np_Raw_Data = np_Raw_Data[np.argsort(np_Raw_Data[:, 0])]

    # Calculate total duration and iterate through each second
    duration = np.floor(np.float32(np_Raw_Data[-1][0]))

    counter = 0
    currentSecond = 60.0

    # Initialize dictionaries and data structures
    packetcount = {}
    TotalPacketDuration = {}
    TotalPacketLength = {}
    src_count = {}
    dst_count = {}
    src_duration = {}
    dst_duration = {}
    src_packet_length_sum = {}
    dst_packet_length_sum = {}
    DioCount = {}
    DisCount = {}
    DaoCount = {}
    OtherMsg = {}
    frame = []

    # Initialize DataFrame
    row = pd.DataFrame(columns=['second', 'src', 'dst', 'packetcount', 'src_ratio', 'dst_ratio',
                                'src_duration_ratio', 'dst_duration_ratio', 'TotalPacketDuration',
                                'TotalPacketLength', 'src_packet_ratio', 'dst_packet_ratio',
                                'DioCount', 'DisCount', 'DaoCount', 'OtherMsg', 'label'])

    # Loop through each second of the capture
    while counter < duration:
        one_second_frame = np_Raw_Data[np.where(np.logical_and(np_Raw_Data[:, 0] >= currentSecond,
                                                               np_Raw_Data[:, 0] <= currentSecond + 1.0))]

        if one_second_frame.size > 1:
            packetcount.clear()
            TotalPacketDuration.clear()
            TotalPacketLength.clear()
            DioCount.clear()
            DisCount.clear()
            DaoCount.clear()
            src_duration.clear()
            dst_duration.clear()
            total_packets = 0
            frame_packet_length_sum = 0
            total_duration = 0.0
            src_packet_length_sum.clear()
            dst_packet_length_sum.clear()
            src_count.clear()
            dst_count.clear()

            for packet in one_second_frame:
                if not pd.isnull(packet[2]):
                    src = packet[2]
                    dst = packet[3]
                    src_dst = src + "-" + dst

                    packetcount[src_dst] = 1 if src_dst not in packetcount else packetcount[src_dst] + 1
                    TotalPacketDuration[src_dst] = packet[1] if src_dst not in TotalPacketDuration else \
                    TotalPacketDuration[src_dst] + packet[1]
                    TotalPacketLength[src_dst] = packet[5] if src_dst not in TotalPacketLength else \
                    TotalPacketLength[src_dst] + packet[5]
                    src_count[src] = 1 if src not in src_count else src_count[src] + 1
                    dst_count[dst] = 1 if dst not in dst_count else dst_count[dst] + 1
                    src_duration[src] = packet[1] if src not in src_duration else src_duration[src] + packet[1]
                    dst_duration[dst] = packet[1] if dst not in dst_duration else dst_duration[dst] + packet[1]
                    total_duration += packet[1]
                    src_packet_length_sum[src] = packet[5] if src not in src_packet_length_sum else \
                    src_packet_length_sum[src] + packet[5]
                    dst_packet_length_sum[dst] = packet[5] if dst not in dst_packet_length_sum else \
                    dst_packet_length_sum[dst] + packet[5]
                    frame_packet_length_sum += packet[5]
                    total_packets += 1

                    if packet[6] == "RPL Control (DODAG Information Object)":
                        DioCount[src_dst] = 1 if src_dst not in DioCount else DioCount[src_dst] + 1
                    if packet[6] == "RPL Control (DODAG Information Solicitation)":
                        DisCount[src_dst] = 1 if src_dst not in DisCount else DisCount[src_dst] + 1
                    if packet[6] == "RPL Control (Destination Advertisement Object)":
                        DaoCount[src_dst] = 1 if src_dst not in DaoCount else DaoCount[src_dst] + 1
                    if ((packet[6] != "RPL Control (Destination Advertisement Object)") and (
                            packet[6] != "RPL Control (DODAG Information Object)") and (
                            packet[6] != "RPL Control (Destination Advertisement Object)")):
                        OtherMsg[src_dst] = 1 if src_dst not in OtherMsg else OtherMsg[src_dst] + 1

            for i in packetcount:
                if i not in DioCount:
                    arr_diocount = 0
                else:
                    arr_diocount = DioCount[i]
                if i not in DisCount:
                    arr_discount = 0
                else:
                    arr_discount = DisCount[i]
                if i not in DaoCount:
                    arr_daocount = 0
                else:
                    arr_daocount = DaoCount[i]
                if i not in OtherMsg:
                    arr_othermsg = 0
                else:
                    arr_othermsg = OtherMsg[i]

                x = i.split("-")
                sourcee = x[0]
                destinatt = x[1]

                src_ratio = src_count[sourcee] / total_packets if total_packets > 0 else 0
                dst_ratio = dst_count[destinatt] / total_packets if total_packets > 0 else 0
                src_duration_ratio = src_duration[sourcee] / total_duration if total_duration > 0 else 0
                dst_duration_ratio = dst_duration[destinatt] / total_duration if total_duration > 0 else 0
                src_packet_ratio = src_packet_length_sum[sourcee] / frame_packet_length_sum if frame_packet_length_sum > 0 else 0
                dst_packet_ratio = dst_packet_length_sum[destinatt] / frame_packet_length_sum if frame_packet_length_sum > 0 else 0

                array = np.array([
                    np.single(currentSecond),
                    ip_dict[sourcee],
                    ip_dict[destinatt],
                    int(packetcount[i]),
                    np.single(src_ratio),
                    np.single(dst_ratio),
                    np.single(src_duration_ratio),
                    np.single(dst_duration_ratio),
                    TotalPacketDuration[i],
                    TotalPacketLength[i],
                    np.single(src_packet_ratio),
                    np.single(dst_packet_ratio),
                    arr_diocount,
                    arr_discount,
                    arr_daocount,
                    arr_othermsg,
                    1 if "MM" in file.name else 0
                ], dtype="object")
                a_series = pd.Series(array, index=row.columns)
                row = pd.concat([row, a_series.to_frame().T], ignore_index=True)

        currentSecond += 1.0
        counter += 1

    return row
    
    
def effectuer_acp(dataframe, n_components=2):
    features = dataframe.drop(columns=['label'])
    labels = dataframe['label']

    # Standardiser les features
    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(features)

    # Effectuer l'ACP
    pca = PCA(n_components=n_components)
    composants_principaux = pca.fit_transform(scaled_features)

    # Créer un DataFrame avec les composantes principales
    pca_df = pd.DataFrame(data=composants_principaux, columns=[f'CP{i+1}' for i in range(n_components)])
    pca_df['label'] = labels.values

    return pca_df, pca
def tracer_visualisations_donnees(dataframe):
    st.subheader('Visualisations des Données')

    # Exemple : Histogramme du nombre de paquets
    #plt.figure(figsize=(10, 6))
    #sns.histplot(dataframe['packetcount'], bins=20, kde=True)
    #plt.xlabel('Nombre de Paquets')
    #plt.ylabel('Fréquence')
    #plt.title('Histogramme du Nombre de Paquets')
    #st.pyplot(plt)

    # Exemple : Diagramme en barres du ratio source vs destination
    #plt.figure(figsize=(12, 8))
    #sns.barplot(x='src_ratio', y='dst_ratio', data=dataframe)
    #plt.xlabel('Ratio Source')
    #plt.ylabel('Ratio Destination')
    #plt.title('Ratio Source vs Destination')
    #st.pyplot(plt)

    # Exemple : Nuage de points 2D
    #plt.figure(figsize=(12, 8))
    #sns.scatterplot(x='src_duration_ratio', y='dst_duration_ratio', hue='label', data=dataframe)
    #plt.xlabel('Ratio Durée Source')
    #plt.ylabel('Ratio Durée Destination')
    #plt.title('Nuage de Points 2D : Ratio Durée Source vs Ratio Durée Destination')
    #st.pyplot(plt)

    # Effectuer l'ACP et tracer les deux premières composantes principales
    pca_df, pca = effectuer_acp(dataframe)
    
    plt.figure(figsize=(12, 8))
    # Ajouter du jitter pour éviter la superposition
    jittered_pca_df = pca_df.copy()
    jittered_pca_df['CP1'] += np.random.normal(0, 0.02, size=pca_df.shape[0])
    jittered_pca_df['CP2'] += np.random.normal(0, 0.02, size=pca_df.shape[0])
    
    sns.scatterplot(x='CP1', y='CP2', hue='label', data=jittered_pca_df, alpha=0.6)
    plt.xlabel('Composante Principale 1')
    plt.ylabel('Composante Principale 2')
    plt.title('Nuage de Points 2D : ACP des Données')
    st.pyplot(plt)

    # Afficher le ratio de variance expliquée
    #st.write('Ratio de Variance Expliquée de chaque Composante Principale :')
    #st.write(pca.explained_variance_ratio_)

def compare_models(merged_df, selected_plot):

    
    if merged_df is not None:
        # Feature importance ranking
        X = merged_df.iloc[:, :-1]  # independent columns
        y = merged_df['label'].astype(int)   # target column i.e., label
        model = RandomForestClassifier(n_estimators=100)
        model.fit(X, y)
        
        # Plot graph of feature importances for better visualization
        #feat_importances = pd.Series(model.feature_importances_, index=X.columns)
        #fig, ax = plt.subplots()
        #feat_importances.nlargest(12).plot(kind='barh', ax=ax)
        #plt.title("Feature Importances")
        #st.pyplot(fig)
        
        # Copy the data into a new variable
        data_copy = merged_df.copy()
        
        # Drop the label column from the data
        data_copy.drop(['label'], axis=1, inplace=True)
        
        # y is the label column
        y = merged_df['label'].astype(int)
        
        # X is the data without the label column
        X = data_copy
        x_train, x_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=15, shuffle=True)
        
        # Standardize the data
        scaler = StandardScaler()
        x_train = scaler.fit_transform(x_train)
        x_test = scaler.transform(x_test)
        
        # Random Forest Classification
        rfstart_time = time.time()  # Obtaining initial time of the training
        rfc = RandomForestClassifier(n_estimators=42, criterion='entropy')  # Creating the Random Forest Classifier object
        rfc.fit(x_train, y_train)  # Training the data
        rfend_time = time.time()  # Obtaining ending time of the training
        RFduration = rfend_time - rfstart_time  # Calculating the duration
        y_pred_rfc = rfc.predict(x_test)  # Predicting data
        cm_rfc = confusion_matrix(y_test, y_pred_rfc)  # Creating confusion matrix
        ar_rfc = accuracy_score(y_test, y_pred_rfc)  # Calculating accuracy rate


        
        

        knnstart_time = time.time()  # Obtaining initial time of the training
        knn = KNeighborsClassifier(n_neighbors=3)  # Creating the KNN Classifier object
        knn.fit(x_train, y_train)  # Training the data
        knnend_time = time.time()  # Obtaining ending time of the training
        knnduration = knnend_time - knnstart_time  # Calculating the duration
        y_pred_knn = knn.predict(x_test)  # Predicting data
        cm_knn = confusion_matrix(y_test, y_pred_knn)  # Creating confusion matrix
        ar_knn = accuracy_score(y_test, y_pred_knn)  # Calculating accuracy rate
        
        if selected_plot == "Random Forest":
            R_accuracies = []
            tree_values = list(range(1, 101, 10))
            for n in tree_values:
                rf = RandomForestClassifier(n_estimators=n, random_state=42)
                rf.fit(x_train, y_train)
                y_pred = rf.predict(x_test)
                R_accuracies.append(accuracy_score(y_test, y_pred))
            rf = RandomForestClassifier(n_estimators=n, random_state=42)
            rf.fit(x_train, y_train)
            y_pred = rf.predict(x_test)
            st.write("### Random Forest Accuracy vs. Number of trees")
            fig, ax = plt.subplots()
            ax.plot(tree_values, R_accuracies, marker='o')
            ax.set_xlabel("Number of trees")
            ax.set_ylabel("Accuracy")
            ax.set_title("Random Forest Accuracy vs. Number of trees")
            st.pyplot(fig)
            
            st.write("## Random Forest Classification Results:")
            st.write(f"Accuracy Rate: :blue[{ar_rfc}]")
            st.write(f"Training Duration: :blue[{RFduration}] seconds")

            # Confusion Matrix visualization
            plt.figure(figsize=(10, 7))
            sns.heatmap(cm_rfc, annot=True, fmt='d', cmap='Blues')
            plt.xlabel('Predicted')
            plt.ylabel('Actual')
            plt.title('Confusion Matrix - Random Forest')
            st.pyplot(plt)

        elif selected_plot == "KNN":
                    # KNN Classifier
            accuracies = []
            k_values = list(range(1, 21))
            for k in k_values:
                knn = KNeighborsClassifier(n_neighbors=k)
                knn.fit(x_train, y_train)
                y_pred = knn.predict(x_test)
                accuracies.append(accuracy_score(y_test, y_pred))
            #st.sidebar.write("## KNN Model")
            #k = st.sidebar.slider("K value", 1, 20, 7)
            knn = KNeighborsClassifier(n_neighbors=k)
            knn.fit(x_train, y_train)
            y_pred = knn.predict(x_test)
        

            st.write("### KNN Accuracy vs. K value")
            fig, ax = plt.subplots()
            plt.plot(k_values, accuracies, marker='o')
            plt.xlabel("K value")
            plt.ylabel("Accuracy")
            plt.title("KNN Accuracy vs. K value")
            st.pyplot(fig)
            

            st.write("## KNN Classification Results:")
            st.write(f"Accuracy Rate: :blue[{ar_knn}]")
            st.write(f"Training Duration: :blue[{knnduration}] seconds")

            # Confusion Matrix visualization
            plt.figure(figsize=(10, 7))
            sns.heatmap(cm_knn, annot=True, fmt='d', cmap='Blues')
            plt.xlabel('Predicted')
            plt.ylabel('Actual')
            plt.title('Confusion Matrix - KNN')
            st.pyplot(plt)
            
        elif selected_plot == "Comparison":
            st.write("## Comparison of Random Forest and KNN:")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("## Random Forest Classification Results:")
                st.write(f"Accuracy Rate: :blue[{ar_rfc}]")
                st.write(f"Training Duration: :blue[{RFduration}] seconds")
                
                # Confusion Matrix visualization for Random Forest
                plt.figure(figsize=(10, 7))
                sns.heatmap(cm_rfc, annot=True, fmt='d', cmap='Blues')
                plt.xlabel('Predicted')
                plt.ylabel('Actual')
                plt.title('Confusion Matrix - Random Forest')
                st.pyplot(plt)
            
            with col2:
                st.write("## KNN Classification Results:")
                st.write(f"Accuracy Rate: :blue[{ar_knn}]")
                st.write(f"Training Duration: :blue[{knnduration}] seconds")
                
                # Confusion Matrix visualization for KNN
                plt.figure(figsize=(10, 7))
                sns.heatmap(cm_knn, annot=True, fmt='d', cmap='Blues')
                plt.xlabel('Predicted')
                plt.ylabel('Actual')
                plt.title('Confusion Matrix - KNN')
                st.pyplot(plt)
        
       # st.sidebar.header("Prediction")
        #pred_file = st.sidebar.file_uploader("Upload a CSV file for prediction", type="csv", key="3")

       # if pred_file is not None:
        #    new_data = pd.read_csv(pred_file, delimiter=';')

            # Ensure the new data has the same preprocessing steps as the training data
         #   new_data.bfill(inplace=True)
          #  new_data = new_data.drop_duplicates(inplace=False)
            
            # Remove label column if present
           # if 'label' in new_data.columns:
            #    new_data.drop(['label'], axis=1, inplace=True)  

            # Normalize the new data
           # new_data = scaler.transform(new_data)

            # Make predictions
           # predictions = rfc.predict(new_data) if selected_plot == "Random Forest" else knn.predict(new_data)
           # st.write("Prediction Results:")
           # st.write(predictions)

           # m = sum(predictions == 1)
           # n = sum(predictions != 1)

            # Determine the presence of attacks
           # if m > n:
            #    st.write("The file contains attacks.")
            #else:
             #   st.write("The file does not contain attacks.")
   # else:
    #    st.write("Please upload both CSV files for training.")
    return knn, rfc, scaler
# Function to plot histograms and other visualizations
def plot_data_visualizations(dataframe):
    st.subheader('Data Visualizations')
    
    # Example: Histogram of packet counts
    plt.figure(figsize=(10, 6))
    sns.histplot(dataframe['packetcount'], bins=20, kde=True)
    plt.xlabel('Packet Count')
    plt.ylabel('Frequency')
    plt.title('Histogram of Packet Counts')
    st.pyplot(plt)
    
    # Example: Bar plot of source vs destination ratios
    plt.figure(figsize=(12, 8))
    sns.barplot(x='src_ratio', y='dst_ratio', data=dataframe)
    plt.xlabel('Source Ratio')
    plt.ylabel('Destination Ratio')
    plt.title('Source vs Destination Ratio')
    st.pyplot(plt)
# Streamlit UI



    

def main():
    st.title("Comparison de K Nearest Neighbor et Random Forest pour la détection des attaques dans IoT")

    uploaded_file_1 = st.file_uploader("Uploader un fichier de simulation normal", type="csv", key="1")
    uploaded_file_2 = st.file_uploader("Uploader un fichier de simulation contient des attaques", type="csv", key="2")

    if uploaded_file_1 is not None and uploaded_file_2 is not None:
        # Selected plot type
        st.sidebar.header("Visualizations")
        plot_options = ["Random Forest", "KNN", "Comparison"]
        selected_plot = st.sidebar.selectbox("choisir une option", plot_options)
        
        # Process file on button click
        if st.button('Process Files'):
            # Process the uploaded files
            result_df_1 = process_pcap(uploaded_file_1)
            result_df_2 = process_pcap(uploaded_file_2)
            #plot_data_visualizations(result_df_1)
            #plot_data_visualizations(result_df_2)
            # Display some results or visualizations
            st.write("## Processed data:")
            st.write(result_df_1.head())
            st.write(result_df_2.head())

            if uploaded_file_1 is not None and uploaded_file_2 is not None:
                merged_df = pd.concat([result_df_1, result_df_2], ignore_index=True)
                st.write('## Merged Analyzed Packet Data')
                st.write(merged_df)
                

                if merged_df is not None and selected_plot:
                    tracer_visualisations_donnees(merged_df)
                    compare_models(merged_df, selected_plot)

                    
            
            
       
                    
                    

            
            


if __name__ == '__main__':
    main()

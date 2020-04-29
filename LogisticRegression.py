#no_feature_selection
import pandas as pd
import numpy as np
from time import time
col_names = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "hot", 
             "num_failed_logins", "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations", 
             "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count", "srv_count", 
             "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", 
             "srv_diff_host_rate", "dst_host_count","dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate", 
             "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate", 
             "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label"]
num_features = ["duration", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", 
                "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
                "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate", 
                "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
                "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate", 
                "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
                "dst_host_rerror_rate", "dst_host_srv_rerror_rate"]
final_columns = ['Protocol_type_icmp', 'Protocol_type_tcp', 'Protocol_type_udp', 'service_IRC', 'service_X11', 'service_Z39_50', 'service_auth', 'service_bgp', 'service_courier', 'service_csnet_ns', 'service_ctf', 'service_daytime', 'service_discard', 'service_domain', 'service_domain_u', 'service_echo', 'service_eco_i', 'service_ecr_i', 'service_efs', 'service_exec', 'service_finger', 'service_ftp', 'service_ftp_data', 'service_gopher', 'service_hostnames', 'service_http', 'service_http_443', 'service_imap4', 'service_iso_tsap', 'service_klogin', 'service_kshell', 'service_ldap', 'service_link', 'service_login', 'service_mtp', 'service_name', 'service_netbios_dgm', 'service_netbios_ns', 'service_netbios_ssn', 'service_netstat', 'service_nnsp', 'service_nntp', 'service_ntp_u', 'service_other', 'service_pm_dump', 'service_pop_2', 'service_pop_3', 'service_printer', 'service_private', 'service_red_i', 'service_remote_job', 'service_rje', 'service_shell', 'service_smtp', 'service_sql_net', 'service_ssh', 'service_sunrpc', 'service_supdup', 'service_systat', 'service_telnet', 'service_tftp_u', 'service_tim_i', 'service_time', 'service_urh_i', 'service_urp_i', 'service_uucp', 'service_uucp_path', 'service_vmnet', 'service_whois', 'flag_OTH', 'flag_REJ', 'flag_RSTO', 'flag_RSTOS0', 'flag_RSTR', 'flag_S0', 'flag_S1', 'flag_S2', 'flag_S3', 'flag_SF', 'flag_SH', 'service_icmp', 'duration', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate']

df = pd.read_csv("C:/Users/shash/Desktop/train.csv", names = col_names)
df_test = pd.read_csv("C:/Users/shash/Desktop/test.csv", header=None, names = col_names)

labeldf=df['label']
labeldf_test=df_test['label']
newlabeldf=labeldf.replace({'neptune.' : 'DoS' ,'back.': 'DoS', 'land.': 'DoS', 'pod.': 'DoS', 'smurf.': 'DoS', 'teardrop.': 'DoS','mailbomb.': 'DoS', 'apache2.': 'DoS', 'processtable.': 'DoS', 'udpstorm.': 'DoS', 'worm.': 'DoS',
                           'ipsweep.' : 'Probe', 'nmap.' : 'Probe', 'portsweep.' : 'Probe', 'satan.' : 'Probe', 'mscan.' : 'Probe', 'saint.' : 'Probe'
                          ,'ftp_write.': 'R2L', 'guess_passwd.': 'R2L' ,'imap.': 'R2L', 'multihop.': 'R2L' ,'phf.': 'R2L' ,'spy.': 'R2L' ,'warezclient.': 'R2L', 'warezmaster.': 'R2L', 'sendmail.': 'R2L', 'named.': 'R2L', 'snmpgetattack.': 'R2L', 'snmpguess.': 'R2L', 'xlock.': 'R2L', 'xsnoop.': 'R2L', 'httptunnel.': 'R2L', 
                         'buffer_overflow.': 'U2R','loadmodule.': 'U2R','perl.': 'U2R','rootkit.': 'U2R','ps.': 'U2R','sqlattack.': 'U2R','xterm.': 'U2R'})
newlabeldf_test=labeldf_test.replace({'neptune.' : 'DoS' ,'back.': 'DoS', 'land.': 'DoS', 'pod.': 'DoS', 'smurf.': 'DoS', 'teardrop.': 'DoS','mailbomb.': 'DoS', 'apache2.': 'DoS', 'processtable.': 'DoS', 'udpstorm.': 'DoS', 'worm.': 'DoS',
                           'ipsweep.' : 'Probe', 'nmap.' : 'Probe', 'portsweep.' : 'Probe', 'satan.' : 'Probe', 'mscan.' : 'Probe', 'saint.' : 'Probe'
                           ,'ftp_write.': 'R2L', 'guess_passwd.': 'R2L' ,'imap.': 'R2L', 'multihop.': 'R2L' ,'phf.': 'R2L' ,'spy.': 'R2L' ,'warezclient.': 'R2L', 'warezmaster.': 'R2L', 'sendmail.': 'R2L', 'named.': 'R2L', 'snmpgetattack.': 'R2L', 'snmpguess.': 'R2L', 'xlock.': 'R2L', 'xsnoop.': 'R2L', 'httptunnel.': 'R2L', 
                           'buffer_overflow.': 'U2R','loadmodule.': 'U2R','perl.': 'U2R','rootkit.': 'U2R','ps.': 'U2R','sqlattack.': 'U2R','xterm.': 'U2R'})
nnewlabeldf=newlabeldf.replace({'normal.' : 'non-R2L', 'Probe' : 'non-R2L', 'U2R' : 'non-R2L', 'DoS' : 'non-R2L'})
nnewlabeldf_test=newlabeldf_test.replace({'normal.' : 'non-R2L', 'Probe' : 'non-R2L', 'U2R' : 'non-R2L', 'DoS' : 'non-R2L'})
df['label'] = nnewlabeldf
df_test['label'] = nnewlabeldf_test

for col_name in df.columns:
    if df[col_name].dtypes == 'object' :
        unique_cat = len(df[col_name].unique())
        #print("Feature '{col_name}' has {unique_cat} categories".format(col_name=col_name, unique_cat=unique_cat))
for col_name in df_test.columns:
    if df_test[col_name].dtypes == 'object' :
        unique_cat = len(df_test[col_name].unique())
        #print("Feature '{col_name}' has {unique_cat} categories".format(col_name=col_name, unique_cat=unique_cat))

unique_protocol=sorted(df.protocol_type.unique())
string1 = 'Protocol_type_'
unique_protocol2=[string1 + x for x in unique_protocol]
unique_service=sorted(df.service.unique())
unique_service_test=sorted(df_test.service.unique())
string2 = 'service_'
unique_service2=[string2 + x for x in unique_service]
unique_service2_test=[string2 + x for x in unique_service_test]
unique_flag=sorted(df.flag.unique())
string3 = 'flag_'
unique_flag2=[string3 + x for x in unique_flag]
dumcols=unique_protocol2 + unique_service2 + unique_flag2
testdumcols=unique_protocol2 + unique_service2_test + unique_flag2

from sklearn.preprocessing import LabelEncoder,OneHotEncoder
categorical_columns=['protocol_type', 'service', 'flag']
df_categorical_values_enc=df[categorical_columns].apply(LabelEncoder().fit_transform)
testdf_categorical_values_enc=df_test[categorical_columns].apply(LabelEncoder().fit_transform)

enc = OneHotEncoder()
df_categorical_values_encenc = enc.fit_transform(df_categorical_values_enc)
df_cat_data = pd.DataFrame(df_categorical_values_encenc.toarray(),columns=dumcols)
testdf_categorical_values_encenc = enc.fit_transform(testdf_categorical_values_enc)
testdf_cat_data = pd.DataFrame(testdf_categorical_values_encenc.toarray(),columns=testdumcols)

trainservice=df['service'].tolist()
testservice= df_test['service'].tolist()
difference=list(set(trainservice) - set(testservice))
difference1=list(set(testservice) - set(trainservice))
string = 'service_'
difference=[string + x for x in difference]
difference1=[string + x for x in difference1]
for col in difference:
    testdf_cat_data[col] = 0
for col in difference1:
    df_cat_data[col] = 0
    
newdf=df.join(df_cat_data)
newdf.drop('flag', axis=1, inplace=True)
newdf.drop('protocol_type', axis=1, inplace=True)
newdf.drop('service', axis=1, inplace=True)
newdf_test=df_test.join(testdf_cat_data)
newdf_test.drop('flag', axis=1, inplace=True)
newdf_test.drop('protocol_type', axis=1, inplace=True)
newdf_test.drop('service', axis=1, inplace=True)

print(newdf_test['label'].value_counts())

features = newdf[final_columns].astype(float)
features1 = newdf_test[final_columns].astype(float)
lab = newdf['label']
lab1 = newdf_test['label']

from sklearn.linear_model import LogisticRegression
clf = LogisticRegression()
t0 = time()
clf.fit(features, lab)
tt = time() - t0
print ("Classifier trained in {} seconds.".format(round(tt, 3)))
t0 = time()
pred = clf.predict(features1)
tt = time() - t0
print ("Predicted in {} seconds".format(round(tt,3)))
from sklearn.metrics import accuracy_score
acc = accuracy_score(pred, lab1)
print ("Accuracy is {}.".format(round(acc,4)))
print(pd.crosstab(lab1, pred, rownames=['Actual attacks'], colnames=['Predicted attacks']))

#Classifier trained in 5.878 seconds.
#Predicted in 0.023 seconds
#Accuracy is 0.9604.
#Predicted attacks  R2L  non-R2L
#Actual attacks                 
#R2L                  3     3053
#non-R2L             10    74225


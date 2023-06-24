from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import OneHotEncoder
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report,confusion_matrix
import pandas as pd
import random
import math
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import GridSearchCV
import pickle
import numpy as np
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt
from sklearn.metrics import mean_squared_error
from sklearn.metrics._classification import recall_score
from imblearn.over_sampling import SMOTE
import json
import datetime
import warnings
warnings.filterwarnings("ignore")

def initial(pop, dim, ub, lb):
    X = np.zeros([pop, dim])
    for i in range(pop):
        for j in range(dim):
            X[i, j] = random.random() * (ub[j] - lb[j]) + lb[j]
            X[i, j] = int(X[i, j])
    return X


'''边界检查函数'''


def BorderCheck(X, ub, lb, pop, dim):
    for i in range(pop):
        for j in range(dim):
            if X[i, j] > ub[j]:
                X[i, j] = ub[j]
            elif X[i, j] < lb[j]:
                X[i, j] = lb[j]
    return X


'''计算适应度函数'''


def CaculateFitness(X):
    pop = X.shape[0]
    fitness = np.zeros([pop, 1])
    for i in range(pop):
        pca=PCA(n_components=int(X[i][0]))
        pca_new=pca.fit_transform(df5.iloc[:,:-2])
        y = df5.iloc[:, -1:]
        X_train, X_test, y_train, y_test = train_test_split(pca_new, y, test_size=0.20,
                                                            random_state=22)
        # Standardization
        transfer = StandardScaler()
        X_train = transfer.fit_transform(X_train)
        X_test = transfer.transform(X_test)

        estimator=KNeighborsClassifier()
        estimator.fit(X_train,y_train.astype('int'))
        y_predict = estimator.predict(X_test)
        error = mean_squared_error(y_test, y_predict)
        fitness[i] = error

    return fitness


'''适应度排序'''


def SortFitness(Fit):
    fitness = np.sort(Fit, axis=0)
    index = np.argsort(Fit, axis=0)
    return fitness, index


'''根据适应度对位置进行排序'''


def SortPosition(X, index):
    Xnew = np.zeros(X.shape)
    for i in range(X.shape[0]):
        Xnew[i, :] = X[index[i], :]
    return Xnew


'''鲸鱼优化算法'''


def WOA(pop, dim, lb, ub, MaxIter):
    X= initial(pop, dim, ub, lb)  # 初始化种群
    fitness = CaculateFitness(X)  # 计算适应度值
    fitness, sortIndex = SortFitness(fitness)  # 对适应度值排序
    X = SortPosition(X, sortIndex)  # 种群排序
    GbestScore = fitness[0]
    GbestPositon = np.zeros([1,dim])
    GbestPositon[0,:] = X[0, :]
    Curve = np.zeros([MaxIter, 1])
    for t in range(MaxIter):
        Leader = X[0, :]  # 领头鲸鱼
        a = 2 - t * (2 / MaxIter)  # 线性下降权重2 - 0
        a2 = -1 + t * (-1 / MaxIter)  # 线性下降权重-1 - -2
        for i in range(pop):
            r1 = random.random()
            r2 = random.random()

            A = 2 * a * r1 - a
            C = 2 * r2
            b = 1
            l = (a2 - 1) * random.random() + 1

            for j in range(dim):

                p = random.random()
                if p < 0.5:
                    if np.abs(A) >= 1:
                        rand_leader_index = min(int(np.floor(pop * random.random() + 1)), pop - 1)
                        X_rand = X[rand_leader_index, :]
                        D_X_rand = np.abs(C * X_rand[j] - X[i, j])
                        X[i, j] = int(X_rand[j] - A * D_X_rand)
                    elif np.abs(A) < 1:
                        D_Leader = np.abs(C * Leader[j] - X[i, j])
                        X[i, j] = int(Leader[j] - A * D_Leader)
                elif p >= 0.5:
                    distance2Leader = np.abs(Leader[j] - X[i, j])
                    X[i, j] = int(distance2Leader * np.exp(b * l) * np.cos(l * 2 * math.pi) + Leader[j])


        X = BorderCheck(X, ub, lb, pop, dim)  # 边界检测
        fitness = CaculateFitness(X)  # 计算适应度值
        fitness, sortIndex = SortFitness(fitness)  # 对适应度值排序
        X = SortPosition(X, sortIndex)  # 种群排序
        # print('fitness:\n',fitness)
        if fitness[0] <= GbestScore:  # 更新全局最优
            GbestScore = fitness[0]
            GbestPositon[0,:] = X[0, :]
        Curve[t] = GbestScore
        # print('iteration is :', t + 1, ';Best parameters:', GbestPositon[0,:], ';Best fitness', GbestScore)
        # print('iteration is :', t + 1, ';Best parameters:', GbestPositon, ';Best fitness', GbestScore)
        print('iteration is :', t + 1, ';Best parameters:', GbestPositon, ';Best fitness', GbestScore)


    return GbestScore, GbestPositon, Curve

'''
'''

# 1.dataset
file_path='Profiling.csv'
data=pd.read_csv(file_path)

# 2.analysis
# print(data.isnull().any())
# print(data.shape)
# print(data.columns)
# X=data.loc[:,['duration', 'protocol_type', 'flag', 'src_bytes',
#        'dst_bytes', 'wrong_fragment', 'hot', 'num_failed_logins', 'logged_in',
#        'num_compromised', 'root_shell', 'su_attempted', 'num_root',
#        'num_file_creations', 'num_shells', 'num_access_files',
#        'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
#        'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
#        'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
#        'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
#        'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
#        'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
#        'dst_host_serror_rate', 'dst_host_srv_serror_rate',
#        'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'class']]
# y=data.loc[:,['service']]
# print(X.shape)
# print(y.shape)
# print('y.head():\n',y.head())
#
# protocol_type_distribution=data['protocol_type'].value_counts()
# service_distribution=data['service'].value_counts()
# flag_distribution=data['flag'].value_counts()
#
#
# plt.pie(protocol_type_distribution,labels=['icmp', 'tcp', 'udp'],autopct='%0.1f%%')
# plt.legend()
# plt.show()
#
# print('service_distribution:\n',service_distribution)
#
# plt.pie(flag_distribution,labels=['OTH', 'REJ', 'RSTO', 'RSTOS0', 'RSTR', 'S0', 'S1', 'S2', 'S3','SF', 'SH'],textprops={'fontsize':0})
# plt.legend()
# plt.show()
# print('flag_distribution:\n',flag_distribution)

# 3.preprocessing
# Missing value

for column in list(data.columns[data.isnull().sum() > 0]):
    mean_val = data[column].mean()
    data[column].fillna(mean_val, inplace=True)


#
# print(data['service'])
# print('data.shape:\n',data.shape)

# onehot
ohe=OneHotEncoder()
df_transformed=ohe.fit_transform(data.loc[:,['protocol_type','flag','class']]).toarray()
df2=pd.DataFrame(df_transformed,columns=['icmp', 'tcp', 'udp','OTH', 'REJ', 'RSTO', 'RSTOS0', 'RSTR', 'S0', 'S1', 'S2', 'S3',
       'SF', 'SH','anomaly', 'normal'])
#
# Replace the original data
df3=data.drop(['protocol_type','flag','class'],axis=1)
df4=pd.concat((df2,df3),axis=1).iloc[:22530,:]
order=['icmp', 'tcp', 'udp', 'OTH', 'REJ', 'RSTO', 'RSTOS0', 'RSTR', 'S0',
       'S1', 'S2', 'S3', 'SF', 'SH', 'anomaly', 'normal', 'duration','src_bytes', 'dst_bytes', 'wrong_fragment', 'hot',
       'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
       'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
       'num_access_files', 'num_outbound_cmds', 'is_host_login',
       'is_guest_login', 'count', 'srv_count', 'serror_rate',
       'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
       'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
       'dst_host_srv_count', 'dst_host_same_srv_rate',
       'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
       'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
       'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
       'dst_host_srv_rerror_rate','service']
df5=df4[order]



X=df5.iloc[:, :-2]
y=df5.iloc[:, -1:]

# print('y==http:\n',y=='http')
h=df5.loc[data['service'] == 'http',-1:] = 1
n=df5.loc[data['service'] != 'http',-1:] = 0



df5=df5.append(df5[:2000],ignore_index=True)
# df5.to_csv('./translated.csv')



pop =5  # 种群数量
MaxIter = 20  # 最大迭代次数
dim = 1  # 维度
lb = 1 * np.ones([dim, 1])  # 下边界
ub = 51 * np.ones([dim, 1])  # 上边界

starttime = datetime.datetime.now()
GbestScore, GbestPositon, Curve = WOA(pop, dim, lb, ub, MaxIter)
# print('最优适应度值：', GbestScore)
# print('最优解：', GbestPositon)
#绘制适应度曲线
# plt.figure(1)
# plt.plot(range(MaxIter),Curve, 'r-', linewidth=2)
# plt.xlabel('Iteration', fontsize='medium')
# plt.ylabel("Fitness", fontsize='medium')
# plt.grid()
# plt.title('WOA', fontsize='large')
# plt.show()



X=df5.iloc[:, :-2]
y=df5.iloc[:, -1:]
service_distribution=df5['service'].value_counts()
print('before:',service_distribution)

pca = PCA(n_components=int(GbestPositon[0,:]))
# pca = PCA(n_components=32)
pca_new = pca.fit_transform(X)


print('pca_new.shape:\n',pca_new.shape)




# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3,random_state=22)
X_train, X_test, y_train, y_test = train_test_split(pca_new, y.astype('int'), test_size=0.3,random_state=22)
# print('type(y_train):\n',type(y_train))
# sm = SMOTE(random_state = 2,k_neighbors=3)
# X_train, y_train = sm.fit_resample(X_train,y_train)

after_distribution=y.value_counts()
print('after:',after_distribution)
print('X_train.shape:\n',X_train.shape)
print('y_train.shape:\n',y_train.shape)



#Standardization
transfer = StandardScaler()
X_train = transfer.fit_transform(X_train)
X_test = transfer.transform(X_test)



estimator = KNeighborsClassifier()
# n_neighbors=range(1,30)
# param_dict={'n_neighbors':n_neighbors}
# estimator=GridSearchCV(estimator,param_grid=param_dict,cv=10)
estimator.fit(X_train, y_train.astype('int'))
with open('./KNN.pickle','wb') as f:
    pickle.dump(estimator,f)

# with open('./KNN.pickle','rb') as f:
#     estimator=pickle.load(f)
endtime = datetime.datetime.now()
print(f"running time:{(endtime - starttime).seconds} second")

score=estimator.score(X_test,y_test.astype('int'))
print('accuracy:\n',score)
# print('best_params:\n',estimator.best_params_)
# print('best_score:\n',estimator.best_score_)
# print('best_estimator:\n',estimator.best_estimator_)
# print('cv_results:\n',estimator.cv_results_)

# plt.plot(n_neighbors,estimator.cv_results_['mean_test_score'])
# plt.xlabel('n_neighbors')
# plt.ylabel('mean_test_score')
# plt.show()
# y_predict = estimator.predict(X_test)
# error = mean_squared_error(y_test, y_predict)
# print('error:\n',error)

y_pred = estimator.predict(X_test)
# confusion_matrix(y_test,y_pred)
# print('confusion_matrix:\n',confusion_matrix)

print('recall_score :\n', recall_score(y_test,y_pred,average='macro'))
print('f1_score:\n',f1_score(y_test, y_pred, average='macro'))
# print(f1_score(y_test, y_pred, average='weighted'))

dict={"pickle_file":"./KNN.pickle",
      "translated_data":"./translated.csv",
      "marked_one_file":"./one.csv",
      "marked_zero_file":"./zero.csv",
      "best_param":int(GbestPositon[0,:])}


with open("./jfile.json","w") as f:
    json_file=json.dumps(dict)
    f.write(json_file)



'''
running time:181 second
accuracy:
 0.9929338225302351
recall_score :
 0.9909677928777603
f1_score:
 0.9922087117592282
 
 25
'''


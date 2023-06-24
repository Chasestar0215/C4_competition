import pickle
import pandas as pd
import datetime
from sklearn.decomposition import PCA
from sklearn.metrics import recall_score, f1_score
from sklearn.model_selection import train_test_split
import json
import warnings

from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")

with open('./jfile.json', 'r') as json_file:
	dict = json.load(json_file)

#读取模型
with open(dict['pickle_file'],'rb') as f:
    estimator=pickle.load(f)
#读取数据
file_path=dict['translated_data']
data=pd.read_csv(file_path)

#开始计时
starttime = datetime.datetime.now()

X=data.iloc[:, :-2]
y=data.iloc[:, -1:]

#PCA降维
pca = PCA(n_components=dict['best_param'])
pca_new = pca.fit_transform(X)


X_train, X_test, y_train, y_test = train_test_split(pca_new, y.astype('int'), test_size=0.3,random_state=22)

#Standardization
transfer = StandardScaler()
X_train = transfer.fit_transform(X_train)
X_test = transfer.transform(X_test)

estimator.fit(X_train, y_train.astype('int'))


score=estimator.score(X_test,y_test.astype('int'))
with open('./KNN.pickle','wb') as f:
    pickle.dump(estimator,f)

endtime = datetime.datetime.now()
print(f"running time:{(endtime - starttime).seconds} second")
print('accuracy:\n',score)
y_pred = estimator.predict(X_test)
print('recall_score :\n', recall_score(y_test,y_pred,average='macro'))
print('f1_score:\n',f1_score(y_test, y_pred, average='macro'))
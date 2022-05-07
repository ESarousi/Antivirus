# Pythonic Virus Anatomy & Computer Defense Report

Hello there! This is an antivirus project, where we discover how Python can scan for files and determine if a file is malicious or not. The model is also tested for accuracy.

## Data Preparation

```python
#loading packages

import matplotlib.pyplot as plt
import numpy as np
import os
import pandas as pd
import pprint
import seaborn as sns
from scipy import stats
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import cross_val_score
from sklearn.tree import DecisionTreeClassifier
import statsmodels.api as sm
```

```python
#Folder used including all files.
folder = os.getcwd()+'/Virus and Good Files/'
```

```python
#Creating a list with all files in the folder.

file_list = []

for file in os.listdir(folder):
    file_list.append(file)
```

```python
#Designating each file as good or virus based on the first letter.

G_list = []
V_list = []

for f in file_list:
    if f[:1] == "G":
        G_list.append(f)
    if f[:1] == "V":
        V_list.append(f)
```

```python
lines = [] #An empty list that will be fed with all lines. 

#Creating a function to remove all triple quotes that throws off model accuracy.
def cleanQuotes(str_data):
    # Where your code starts:
    cleaned_data = ""
    delete_mode = False
    for i, char in enumerate(str_data):
        window = str_data[i : i+3] #Creates a three-index window that, with ''', will toggle the delete mode.
        if window == '"""':
            if delete_mode:
                delete_mode = False
            else:
                # Enter delete mode
                delete_mode = True
        if delete_mode:
            continue
        else:
            cleaned_data += char
    cleaned_data = cleaned_data.split("\n")
    final_data = ""

    for line in cleaned_data:
        if '"""' in line:
            continue
        else:
            final_data += line + "\n"
    return final_data

res = cleanQuotes(''.join(lines))
```

```python
results = {} # A dictionary filled with results.
Classification = np.asarray([]) # Good vs. Bad files.
file_list_lines = [] # Stored filed content.

for file in file_list:
    lines = []
    try:
        with open(folder+file, "r", encoding = "utf-8") as f: # Opening the file.
            for line in f:
                if line[0] == '#':
                    line.replace(line, '\n')
                if line[0] == '\n\n':
                    line.replace(line, '\n')
                lines.append(line) # Storing the file's text..
            l = cleanQuotes("".join(lines))
            file_list_lines.append(l.split("\n"))
        if file[0][0] == "G":
            Classification = np.append(Classification, 0) # Not a virus
        else:
            Classification = np.append(Classification, 1) # Virus
    except:
        pass

file_list_strings = ['\n'.join(lines) for lines in file_list_lines] #Joining all strings.
```

## Working with Data Frames

```python
df = pd.DataFrame(data=zip(file_list_strings,Classification), columns=['File', 'Classification'])
```

```python
vectorizer = CountVectorizer() 
file_vectors = vectorizer.fit_transform(file_list_strings)
#Using a count vectorizer to gain a proper count.
vectorizer.get_feature_names()
```

```python
data = pd.DataFrame.sparse.from_spmatrix(file_vectors).sparse.to_dense() #Turns the vectors binary for counting.
data.columns = list(vectorizer.get_feature_names()) #A new df. All columns are unique words.
data.head()
```

```python
binary_data = (data > 0) + 0 #Removing empty data.
binary_data['Classification'] = Classification
binary_data
```

```python
#A new df where the instances of each word will be counted and differentiated between good and virus.

words_by_class = binary_data.groupby('Classification').sum().transpose()
words_by_class.columns=['Good', 'Virus']

df['Classification'].value_counts()
n_virus = df['Classification'].value_counts()
n_virus = n_virus[1]

n_good = df['Classification'].value_counts()
n_good = n_good[0]

words_by_class['Good %'] = words_by_class['Good']/n_good
words_by_class['Virus %'] = words_by_class['Virus']/n_virus
words_by_class['Total'] = words_by_class['Good'] + words_by_class['Virus']
words_by_class['Difference %'] = words_by_class['Good %'] - words_by_class['Virus %']

words_by_class.sort_values('Difference %')
```

```python
good_pd = words_by_class.sort_values('Difference %').tail(n=10)
good_kw = good_pd.index.values.tolist()
good_pd['Classification'] = 'Good'
good_pd
```

```python
virus_pd = words_by_class.sort_values('Difference %').head(n=10)
virus_kw = virus_pd.index.values.tolist()
virus_pd['Classification'] = 'Virus'
virus_pd
```

```python
#Creating a new df to use for the graphic.

comb_df = pd.concat([virus_pd, good_pd])
```

## Visualization

```python
#This graphic displays the range of keyword associations to its corresponding classification.

sns.set(rc={'figure.figsize':(20,8.27), 'axes.facecolor': 'lightgrey'}, font_scale = 1.4)
plt.xticks(rotation=45)
sns.barplot(data=comb_df, x=comb_df.index, y='Difference %', palette='vlag_r')
```

## Logistic Regression

```python
#Logistic regression for good keywords

X = data[[x.lower() for x in good_kw if x in data.columns]]
sm_model = sm.Logit(df['Classification'], sm.add_constant(X)).fit(disp=0)
print(sm_model.pvalues)
sm_model.summary()
```

```python
#Logistic regression for virus keywords.

X = data[[x.lower() for x in virus_kw if x in data.columns]]
sm_model = sm.Logit(df['Classification'], sm.add_constant(X)).fit(disp=0)
print(sm_model.pvalues)
sm_model.summary()
```

## Model Evaluation

```python
#Creating a decision tree for further classification and model evaluation.

dec_tree = DecisionTreeClassifier(random_state=0)
cvs = list(cross_val_score(dec_tree, X, df['Classification'], cv=20))

def Average(cross_val_score_list): #A function to find the average of the list.
    return round(sum(cross_val_score_list) / len(cross_val_score_list),3)*100

Average(cvs)
```

## Creating the Antivirus Function

```python
#The antivirus function.

def AntiVirus(t_import_weight, b_word_weight, s_word_weight, threshold_weight, thresh, file_list_lines, classification, debug=False):
    file_string = ""
    classifications = classification
    output_list = np.asarray([])
    
    for file in file_list_lines:     
        threshold = thresh * threshold_weight
        total_imports = 0
        safe_words = 0
        bad_words = 0
        
        for line in file:
            # Import counts
            if "import" in line:
                total_imports += 1
            # Bad Lib checks
            
            # Safe Words
            for kw in good_kw:
                if kw.lower() in line.lower():
                    safe_words += 1
            # Bad Words
            for kw in virus_kw:
                if kw.lower() in line.lower():
                    bad_words += 1

        # For this file, calculate the total score:
        total = (total_imports * t_import_weight) + (bad_words * b_word_weight) - (safe_words * s_word_weight)

        if debug:
            print('''
            File: '''+ str(file[:10]))
            print("Length: ", len(file))
            print("Imports/BadWords/BadImports/SafeWords")
            print(total_imports, "/", bad_words, "/", safe_words)
            print("======== Total Score: " + str(round(total, 3)), "/", threshold)
            #print("Total marks: " + str(total_imports),str(bad_words),str(bad_imports),str(safe_words))

        if total > threshold:
            output_list = np.append(output_list, 1) # Virus
            if debug:
                print("++ Malware!")
        else:
            output_list = np.append(output_list, 0) # Not a virus
            if debug:
                print("-- Not Malware")
                
    a1 = classifications
    a2 = output_list
    count = np.count_nonzero(np.logical_not(np.logical_xor(a1, a2)))
    #A logical gate that flags mismatches between classification and how the function designates the file.
    
    return(round(count/len(file_list_lines),6) * 100)

AntiVirus(2, 7, 9, 1, 8, file_list_lines, Classification)
```

## Testing the Antivirus Accuracy

```python
results = {}
for i in range(1, 3):
    print(i)
    for j in range(1, 15):
        for k in range(1, 20):
            for l in range(1, 15):
                for m in range(1, 20):
                    results[(i, j, k, l, m)] = AntiVirus(i, j, k, l, m, file_list_lines, Classification)
pprint.pprint(sorted(results.items(), key=lambda x: x[1], reverse=True))
```

Thanks so much for reading!

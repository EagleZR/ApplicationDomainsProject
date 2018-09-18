# def get_length(s):
#     length = 0
#
#     for c in s:
#         length += 1
#
#     return length
#
#
# s = "This is a test"
#
# print(get_length(s))
# print(str(len(s)))


# def cate_letters(list_of_strings):
#     list_of_length_2 = []
#     list_of_length_3 = []
#     list_of_length_4 = []
#     for s in list_of_strings:
#         if len(s) == 2:
#             list_of_length_2.append(s)
#         if len(s) == 3:
#             list_of_length_3.append(s)
#         if len(s) == 4:
#             list_of_length_4.append(s)
#     return list_of_length_2, list_of_length_3, list_of_length_4
#
#
# list_of_strings = ['rt', 'asdf', 'ton', 'user', 'er']
# letter_2, letter_3, letter_4 = cate_letters(list_of_strings)
#
# print("Letter 2: " + str(letter_2))
# print("Letter 3: " + str(letter_3))
# print("Letter 4: " + str(letter_4))


def check_legit_ISBN(ISBNLis):
    total = 0
    for i in range(1, len(ISBNLis)):
        calc = ISBNLis[10-i] * i
        total += calc
    if total % 11 == 0:
        return "Legit"
    else:
        return "Not Legit"


yes = [0, 2, 0, 1, 3, 1, 4, 5, 2, 5]
no = [0, 2, 0, 1, 3, 1, 4, 5, 2, 3]

print(check_legit_ISBN(yes))
print(check_legit_ISBN(no))

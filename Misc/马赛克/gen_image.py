from PIL import Image, ImageDraw, ImageFont

flag = r'catctf{fU11=cO10R=uNc3n5oReD=83ar}'

H = 68
W = 28

canvas = Image.new('RGB', (W * len(flag), H), (255, 255, 255))
font = ImageFont.truetype(
    './sarasa-fixed-sc-regular.ttf', 56, encoding='utf-8')
pen = ImageDraw.Draw(canvas)
pen.text((0, 0), flag, 'black', font)

canvas.save('flag_uncensored.png', format='png')


# for i in range(len(flag)):
#     char = canvas.crop((W * i, 0, W * (i+1), H))
#     char.save(f'./tmp_char/char_{i}.png')

def mosaic_img(img: Image.Image, L, H, R, D):
    w, h = R - L, D - H
    a = [0, 0, 0]
    cnt = 0
    for x in range(w):
        for y in range(h):
            j = img.getpixel((L+x, H+y))
            for ch in range(len(a)):
                a[ch] += j[ch]
            cnt += 1
    b = [k//cnt for k in a]
    mosaic = Image.new('RGB', (w, h), tuple(b))
    img.paste(mosaic, (L, H, R, D))


for i in range(7, len(flag)-1):
    mosaic_img(canvas, W*i, 0, W*i+W, H//2)
    mosaic_img(canvas, W*i, H//2, W*i+W, H)

# for i in range(7, len(flag)-1):
#     char = canvas.crop((W * i, 0, W * (i+1), H))
#     w, h = char.size
#     a = [0, 0, 0]
#     cnt = 0
#     for x in range(w):
#         for y in range(h):
#             j = char.getpixel((x, y))
#             for ch in range(len(a)):
#                 a[ch] += j[ch]
#             cnt += 1
#     b = [k//cnt for k in a]
#     print(cnt, b)
#     mosaic = Image.new('RGB', (W, H), tuple(b))
#     canvas.paste(mosaic, (W*i, 0, W*(i+1), H))

canvas.save('flag_censored.png', format='png')

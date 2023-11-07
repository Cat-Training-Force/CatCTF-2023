from PIL import Image, ImageDraw, ImageFont

H = 68
W = 28

font = ImageFont.truetype(
    './sarasa-fixed-sc-regular.ttf', 56, encoding='utf-8')


def get_char_img(ch):
    canvas = Image.new('RGB', (W, H), (255, 255, 255))
    pen = ImageDraw.Draw(canvas)
    pen.text((0, 0), ch, 'black', font)
    return canvas


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


def get_char_mosaic(ch):
    img = get_char_img(ch)
    mosaic_img(img, 0, 0, W, H//2)
    mosaic_img(img, 0, H//2, W, H)
    return img


def check_img_eq(img1: Image.Image, img2: Image.Image, threshold=1):
    assert img1.size == img2.size
    mse = 0
    cnt = 0
    w, h = img1.size
    for x in range(w):
        for y in range(h):
            cnt += 1
            for i in range(3):
                mse += (img1.getpixel((x, y))
                        [i] - img2.getpixel((x, y))[i]) ** 2
    return mse < threshold * cnt


chars = [chr(i) for i in range(32, 126+1)]

char_imgs = {
    ch: get_char_mosaic(ch) for ch in chars
}

ans = ''

flag_img = Image.open('./flag_censored.png')
n = flag_img.size[0]//W
print(flag_img.size, n)

for i in range(7, n-1):
    char = flag_img.crop((W * i, 0, W * (i+1), H))
    # print(i, char.size)
    for k, v in char_imgs.items():
        if check_img_eq(char, v):
            ans += k
            break
    else:
        raise Exception("no char match")

ans = 'catctf{'+ans+'}'
print(ans)

flag = r'catctf{fU11=cO10R=uNc3n5oReD=83ar}'
assert ans == flag

FROM sgaroncse/v3_service_base_dev:3.3.6

ENV SERVICE_PATH alsvc_pixaxe.Pixaxe
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
  libjpeg-dev \
  python-numpy \
  python-scipy \
  python-matplotlib \
  imagemagick \
  tesseract-ocr \
  tesseract-ocr-all

RUN pip install \
  Pillow \
  awscli

# AWS S3 credentials
ENV AWS_ACCESS_KEY_ID=AKIAIIESFCKMSXUP6KWQ
ENV AWS_SECRET_ACCESS_KEY=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
ENV AWS_REGION=us-east-1

# Download the support files from Amazon S3
RUN aws s3 cp s3://assemblyline-support/Image-ExifTool-11.16.tar.gz /tmp

RUN tar -zxvf /tmp/Image-ExifTool-11.16.tar.gz -C /tmp
RUN cd /tmp/Image-ExifTool-11.16 \
RUN perl /tmp/Image-ExifTool-11.16/Makefile.PL
RUN make -C /tmp/Image-ExifTool-11.16 install

# Clone Pixaxe service code
WORKDIR /opt/al/al_services
RUN git clone -b prod_3.3 https://bitbucket.org/cse-assemblyline/alsvc_pixaxe.git
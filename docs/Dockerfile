FROM ruby:3.4.2

RUN groupadd -r jekyll && useradd -r -g jekyll jekyll

RUN gem install jekyll bundler

WORKDIR /app
COPY Gemfile ./
RUN bundle install

COPY . .

RUN chown -R jekyll:jekyll /app

USER jekyll

EXPOSE 4000
CMD ["bundle", "exec", "jekyll", "serve", "--watch", "--source", "/app", "--port", "4000", "--host", "0.0.0.0"]

# Run this command to start the container:
# docker build -t luminaut-docs . && docker run -p 4000:4000 luminaut-docs

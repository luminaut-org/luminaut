FROM ruby:3.4.2

RUN gem install jekyll bundler && mkdir -p /app


COPY Gemfile /app
WORKDIR /app

RUN bundle install

COPY . /app

EXPOSE 4000
CMD ["bundle", "exec", "jekyll", "serve", "--watch", "--source", "/app", "--port", "4000", "--host", "0.0.0.0"]

# Run this command to start the container:
# docker build -t luminaut-docs . && docker run -p 4000:4000 luminaut-docs
